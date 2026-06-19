package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

	reports := []struct {
		name string
		lang reportLanguage
	}{
		{name: "report.html", lang: zhReportLanguage()},
		{name: "report_en.html", lang: enReportLanguage()},
	}
	for _, r := range reports {
		path := filepath.Join(reportDir, r.name)
		if err := writeLLMStandaloneReport(path, results, r.lang); err != nil {
			return "", err
		}
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

func writeLLMStandaloneReport(path string, results []*models.LLMServer, lang reportLanguage) error {
	data := unifiedReport{
		Lang:        lang,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		LLMSummary:  summarizeLLMResults(results),
		LLMServers:  buildUnifiedLLMServers(results),
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create LLM HTML report: %w", err)
	}
	defer f.Close()

	if err := standaloneLLMTemplate.Execute(f, data); err != nil {
		return fmt.Errorf("render LLM HTML report: %w", err)
	}
	return nil
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
	b.WriteString("# AgentScan LLM 扫描发现\n")
	b.WriteString("# URL\t框架\t版本\t认证\t风险\t模型数\n\n")
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
	b.WriteString("# AgentScan LLM 暴露模型列表\n")
	b.WriteString("# URL\t框架\t模型ID\n\n")
	for _, r := range results {
		for _, m := range r.Models {
			fmt.Fprintf(&b, "%s\t%s\t%s\n", r.URL, r.Framework, m.ID)
		}
	}
	return b.String()
}

func buildLLMEvidenceText(results []*models.LLMServer) string {
	var b strings.Builder
	b.WriteString("# AgentScan LLM 探测证据\n\n")
	for _, r := range results {
		fmt.Fprintf(&b, "## %s (%s)\n", r.URL, r.Framework)
		for _, ep := range r.Evidence.MatchedEndpoints {
			matched := "✗"
			if ep.Matched {
				matched = "✓"
			}
			matchLabel := ""
			if ep.Matched {
				matchLabel = "命中"
			}
			fmt.Fprintf(&b, "  %s %s %s → %d (%.0fms) %s\n",
				matched, ep.Method, ep.Path, ep.StatusCode, ep.ResponseMs, matchLabel)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func buildLLMSummaryText(results []*models.LLMServer) string {
	summary := summarizeLLMResults(results)
	var b strings.Builder
	b.WriteString("AgentScan LLM 扫描摘要\n")
	b.WriteString("==========================\n\n")
	fmt.Fprintf(&b, "发现总数:      %d\n", summary.Total)
	fmt.Fprintf(&b, "开放(无认证):  %d\n", summary.Open)
	fmt.Fprintf(&b, "需要认证:      %d\n", summary.AuthRequired)
	fmt.Fprintf(&b, "严重风险:      %d\n", summary.Critical)
	fmt.Fprintf(&b, "高危风险:      %d\n", summary.High)
	fmt.Fprintf(&b, "中危风险:      %d\n", summary.Medium)
	fmt.Fprintf(&b, "暴露模型:      %d\n", summary.TotalModels)
	return b.String()
}

func createLLMReportDir(baseDir string, targets []string, filePath string) (string, error) {
	return createReportDir(baseDir, targets, filePath)
}
