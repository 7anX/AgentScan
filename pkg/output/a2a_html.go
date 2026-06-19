package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentscan/agentscan/pkg/models"
)

// WriteA2AHTMLReports writes standalone A2A reports (used by agentscan a2a command).
// The report uses the same light theme as MCP reports.
func WriteA2AHTMLReports(results []*models.A2AServer, baseDir string, targets []string, filePath string) (string, error) {
	reportDir, err := createA2AReportDir(baseDir, targets, filePath)
	if err != nil {
		return "", err
	}

	reports := []struct {
		name string
		lang reportLanguage
	}{
		{name: "report.html", lang: zhReportLanguage()},
		{name: "report_en.html", lang: enReportLanguage()},
	}

	for _, r := range reports {
		path := filepath.Join(reportDir, r.name)
		if err := writeA2AStandaloneReport(path, results, r.lang); err != nil {
			return "", err
		}
	}
	// summary.txt for A2A-only reports
	if err := os.WriteFile(filepath.Join(reportDir, "summary.txt"), []byte(buildA2ASummaryText(results)), 0644); err != nil {
		return "", fmt.Errorf("write summary.txt: %w", err)
	}
	if err := writeA2ATextReports(reportDir, results); err != nil {
		return "", err
	}

	return reportDir, nil
}

func createA2AReportDir(baseDir string, targets []string, filePath string) (string, error) {
	if baseDir == "" {
		baseDir = "."
	}
	ts := time.Now().Format("20060102-150405")
	targetSlug := reportTargetSlug(targets)
	if targetSlug == "" && filePath != "" {
		base := filepath.Base(filePath)
		ext := filepath.Ext(base)
		targetSlug = sanitizeSlug(strings.TrimSuffix(base, ext))
	}
	var base string
	if targetSlug != "" {
		base = "agentscan-a2a-" + targetSlug + "-" + ts
	} else {
		base = "agentscan-a2a-" + ts
	}
	path := filepath.Join(baseDir, base)
	for i := 1; ; i++ {
		err := os.Mkdir(path, 0755)
		if err == nil {
			return path, nil
		}
		if !os.IsExist(err) {
			return "", fmt.Errorf("create A2A report directory: %w", err)
		}
		path = filepath.Join(baseDir, fmt.Sprintf("%s-%02d", base, i))
	}
}

func writeA2AStandaloneReport(path string, results []*models.A2AServer, lang reportLanguage) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create A2A HTML report: %w", err)
	}
	defer f.Close()
	return writeA2ASection(f, results, lang, true)
}

func writeA2ATextReports(reportDir string, results []*models.A2AServer) error {
	files := map[string]string{
		"a2a_findings.txt":      buildA2AFindingsText(results, func(*models.A2AServer) bool { return true }),
		"a2a_no_auth.txt":       buildA2AFindingsText(results, func(s *models.A2AServer) bool { return s.NoAuth }),
		"a2a_auth_required.txt": buildA2AFindingsText(results, func(s *models.A2AServer) bool { return s.AuthRequired }),
		"a2a_skills.txt":        buildA2ASkillsText(results),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(reportDir, name), []byte(content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func buildA2ASummaryText(results []*models.A2AServer) string {
	s := summarizeA2AResults(results)
	var b strings.Builder
	fmt.Fprintf(&b, "AgentScan A2A summary\n")
	fmt.Fprintf(&b, "Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "Total: %d\n", s.Total)
	fmt.Fprintf(&b, "Confirmed: %d\n", s.Confirmed)
	fmt.Fprintf(&b, "Public cards: %d\n", s.PublicCards)
	fmt.Fprintf(&b, "No-auth JSON-RPC: %d\n", s.NoAuthJSONRPC)
	fmt.Fprintf(&b, "Auth required: %d\n", s.AuthRequired)
	fmt.Fprintf(&b, "Endpoint disabled: %d\n", s.EndpointDisabled)
	fmt.Fprintf(&b, "Private host advertised: %d\n", s.PrivateHostAdvertised)
	fmt.Fprintf(&b, "Probable discoveries: %d\n", s.ProbableAgentDiscoveries)
	fmt.Fprintf(&b, "Total skills: %d\n", s.TotalSkills)
	return b.String()
}

func buildA2AFindingsText(results []*models.A2AServer, include func(*models.A2AServer) bool) string {
	var b strings.Builder
	for _, s := range results {
		if !include(s) {
			continue
		}
		name := s.AgentName
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\tskills=%d\tscore=%.2f\t%s\n",
			string(s.ExposureStatus),
			s.CardURL,
			string(s.Profile),
			name,
			s.SkillCount,
			s.FingerprintScore,
			strings.Join(s.ExposureSignals, ","),
		)
	}
	return b.String()
}

func buildA2ASkillsText(results []*models.A2AServer) string {
	var b strings.Builder
	for _, s := range results {
		for _, skill := range s.Skills {
			fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n",
				s.CardURL,
				skill.ID,
				skill.Name,
				skill.Description,
			)
		}
	}
	return b.String()
}
