package output

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentscan/agentscan/pkg/models"
)

func TestWriteA2AHTMLReportsCreatesChineseEnglishAndTextFiles(t *testing.T) {
	results := []*models.A2AServer{
		{
			IP:               "93.184.216.34",
			Port:             443,
			Hostname:         "example.com",
			URL:              "https://example.com",
			CardURL:          "https://example.com/.well-known/agent-card.json",
			CardPath:         "/.well-known/agent-card.json",
			Profile:          models.A2AProfileAgentCard,
			ExposureStatus:   models.A2AExposureJSONRPCNoAuth,
			ExposureSignals:  []string{"no_auth_jsonrpc_method_not_found", "official_agent_card"},
			A2AConfirmed:     true,
			FingerprintScore: 0.90,
			NoAuth:           true,
			AgentName:        "Example Agent",
			Description:      "A test agent",
			ProtocolVersion:  "1.0",
			SkillCount:       2,
			Skills: []models.A2ASkill{
				{ID: "search", Name: "Search", Description: "Search the web"},
				{ID: "summarize", Name: "Summarize", Description: "Summarize content"},
			},
			Interfaces: []models.A2AInterface{
				{
					URL:     "https://example.com/a2a",
					Binding: "JSONRPC",
					Status:  models.A2AStatusNoAuthJSONRPCReachable,
				},
			},
			TLSEnabled: true,
			ScanTime:   time.Now(),
			Evidence: models.A2AEvidence{
				Card: models.A2ACardEvidence{
					URL:        "https://example.com/.well-known/agent-card.json",
					StatusCode: 200,
				},
				Fingerprint: models.A2AFingerprintEvidence{
					Score:   0.90,
					Signals: []string{"skills", "capabilities", "official_agent_card"},
				},
				Auth: models.A2AAuthEvidence{
					Declared: "declared_none",
					Status:   string(models.A2AExposureJSONRPCNoAuth),
					Reasons:  []string{"card fetched and parsed", "JSON-RPC unknown-method probe returned without auth"},
				},
			},
		},
	}

	dir, err := WriteA2AHTMLReports(results, t.TempDir(), []string{"example.com"}, "")
	if err != nil {
		t.Fatalf("WriteA2AHTMLReports() error = %v", err)
	}

	zh := readFileForTest(t, filepath.Join(dir, "report.html"))
	en := readFileForTest(t, filepath.Join(dir, "report_en.html"))

	for _, item := range []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "zh",
			content: zh,
			want: []string{
				"AgentScan 扫描报告",
				"badge-a2a",
				"Example Agent",
				"无认证 JSON-RPC",       // translated exposure status
				"官方 agent-card.json", // translated profile
				"Search",
				"未声明认证", // translated declared_none
			},
		},
		{
			name:    "en",
			content: en,
			want: []string{
				"AgentScan Report",
				"badge-a2a",
				"Example Agent",
				"confirmed_a2a_jsonrpc_no_auth",
				"confirmed_a2a_agent_card",
				"Search",
				"declared_none",
				"no_auth_jsonrpc_method_not_found",
			},
		},
	} {
		for _, want := range item.want {
			if !strings.Contains(item.content, want) {
				t.Fatalf("%s report missing %q", item.name, want)
			}
		}
	}

	summary := readFileForTest(t, filepath.Join(dir, "summary.txt"))
	noAuth := readFileForTest(t, filepath.Join(dir, "a2a", "no_auth.txt"))
	allFindings := readFileForTest(t, filepath.Join(dir, "a2a", "findings.txt"))
	skills := readFileForTest(t, filepath.Join(dir, "a2a", "skills.txt"))

	for _, item := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "summary", content: summary, want: "No-auth JSON-RPC: 1"},
		{name: "a2a_no_auth", content: noAuth, want: "confirmed_a2a_jsonrpc_no_auth"},
		{name: "a2a_findings", content: allFindings, want: "confirmed_a2a_agent_card"},
		{name: "a2a_skills", content: skills, want: "Search the web"},
	} {
		if !strings.Contains(item.content, item.want) {
			t.Fatalf("%s missing %q\n%s", item.name, item.want, item.content)
		}
	}
}
