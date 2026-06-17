package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/agentscan/agentscan/pkg/models"
)

// JSONReport 完整 JSON 报告结构
type JSONReport struct {
	Version string              `json:"version"`
	Summary JSONSummary         `json:"summary"`
	Results []*models.MCPServer `json:"results"`
}

// JSONSummary 扫描摘要
type JSONSummary struct {
	Total                 int `json:"total"`
	Unauthenticated       int `json:"unauthenticated"`
	AuthRequired          int `json:"auth_required"`
	Honeypots             int `json:"honeypots"`
	TotalTools            int `json:"total_tools"`
	TotalResources        int `json:"total_resources"`
	TotalResourceTemplates int `json:"total_resource_templates"`
	TotalPrompts          int `json:"total_prompts"`
}

// WriteJSON 输出 JSON 报告到文件或 stdout
func WriteJSON(results []*models.MCPServer, path string) error {
	summary := JSONSummary{Total: len(results)}
	for _, r := range results {
		if r.NoAuth {
			summary.Unauthenticated++
		}
		if r.AuthRequired {
			summary.AuthRequired++
		}
		if r.Honeypot.Suspected {
			summary.Honeypots++
		}
		summary.TotalTools += r.ToolCount
		summary.TotalResources += r.ResourceCount
		summary.TotalResourceTemplates += r.ResourceTemplateCount
		summary.TotalPrompts += r.PromptCount
	}

	report := JSONReport{
		Version: "1.0",
		Summary: summary,
		Results: results,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	if path == "" || path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}

	return os.WriteFile(path, data, 0600)
}
