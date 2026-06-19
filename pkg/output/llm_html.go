package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/agentscan/agentscan/pkg/models"
)

// WriteLLMHTMLReports writes standalone LLM reports (HTML + TXT).
// Returns the report directory path or empty string if no results.
func WriteLLMHTMLReports(results []*models.LLMServer, baseDir string, targets []string, filePath string) (string, error) {
	if len(results) == 0 {
		return "", nil
	}

	reportDir, err := createLLMReportDir(baseDir, targets, filePath)
	if err != nil {
		return "", err
	}

	// Write text reports
	if err := writeLLMTextReports(reportDir, results); err != nil {
		return "", err
	}

	// Write summary.txt
	summary := buildLLMSummaryText(results)
	if err := os.WriteFile(filepath.Join(reportDir, "summary.txt"), []byte(summary), 0644); err != nil {
		return "", fmt.Errorf("write summary.txt: %w", err)
	}

	return reportDir, nil
}

// writeLLMTextReports generates all LLM text report files.
func writeLLMTextReports(reportDir string, results []*models.LLMServer) error {
	files := map[string]string{
		"llm_findings.txt":      buildLLMFindingsText(results, nil),
		"llm_no_auth.txt":       buildLLMFindingsText(results, func(s *models.LLMServer) bool { return s.AuthStatus == "open" }),
		"llm_auth_required.txt": buildLLMFindingsText(results, func(s *models.LLMServer) bool { return s.AuthStatus == "auth_required" }),
		"llm_models.txt":        buildLLMModelsText(results),
		"llm_evidence.txt":      buildLLMEvidenceText(results),
	}

	for name, content := range files {
		if content == "" {
			continue
		}
		path := filepath.Join(reportDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func buildLLMFindingsText(results []*models.LLMServer, filter func(*models.LLMServer) bool) string {
	var b strings.Builder
	b.WriteString("# AgentScan LLM Findings\n")
	b.WriteString("# URL\tFramework\tVersion\tAuth\tRisk\tModels\n\n")
	for _, r := range results {
		if filter != nil && !filter(r) {
			continue
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%d\n",
			r.URL, r.Framework, r.FrameworkVersion, r.AuthStatus, r.RiskLevel, r.ModelCount)
	}
	return b.String()
}

func buildLLMModelsText(results []*models.LLMServer) string {
	var b strings.Builder
	b.WriteString("# AgentScan LLM Models\n")
	b.WriteString("# URL\tFramework\tModelID\n\n")
	for _, r := range results {
		for _, m := range r.Models {
			fmt.Fprintf(&b, "%s\t%s\t%s\n", r.URL, r.Framework, m.ID)
		}
	}
	return b.String()
}

func buildLLMEvidenceText(results []*models.LLMServer) string {
	var b strings.Builder
	b.WriteString("# AgentScan LLM Evidence\n\n")
	for _, r := range results {
		fmt.Fprintf(&b, "## %s (%s)\n", r.URL, r.Framework)
		for _, ep := range r.Evidence.MatchedEndpoints {
			matched := "✗"
			if ep.Matched {
				matched = "✓"
			}
			fmt.Fprintf(&b, "  %s %s %s → %d (%.0fms) %s\n",
				matched, ep.Method, ep.Path, ep.StatusCode, ep.ResponseMs,
				func() string {
					if ep.Matched {
						return "MATCHED"
					}
					return ""
				}())
		}
		b.WriteString("\n")
	}
	return b.String()
}

func buildLLMSummaryText(results []*models.LLMServer) string {
	summary := summarizeLLMResults(results)
	var b strings.Builder
	b.WriteString("AgentScan LLM Scan Summary\n")
	b.WriteString("==========================\n\n")
	fmt.Fprintf(&b, "Total findings:    %d\n", summary.Total)
	fmt.Fprintf(&b, "Open (no auth):    %d\n", summary.Open)
	fmt.Fprintf(&b, "Auth required:     %d\n", summary.AuthRequired)
	fmt.Fprintf(&b, "Critical risk:     %d\n", summary.Critical)
	fmt.Fprintf(&b, "High risk:         %d\n", summary.High)
	fmt.Fprintf(&b, "Medium risk:       %d\n", summary.Medium)
	fmt.Fprintf(&b, "Total models:      %d\n", summary.TotalModels)
	return b.String()
}

func createLLMReportDir(baseDir string, targets []string, filePath string) (string, error) {
	return createReportDir(baseDir, targets, filePath)
}
