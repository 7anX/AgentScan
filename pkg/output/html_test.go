package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentscan/agentscan/pkg/models"
)

func TestWriteHTMLReportsCreatesChineseAndEnglishReports(t *testing.T) {
	results := []*models.MCPServer{
		{
			IP:                    "127.0.0.1",
			Port:                  8001,
			URL:                   "http://127.0.0.1:8001",
			Endpoint:              "/mcp",
			Transport:             models.TransportStreamableHTTP,
			FingerprintScore:      0.85,
			NoAuth:                true,
			ServerName:            "demo",
			ServerVersion:         "1.0.0",
			ProtocolVersion:       "2025-06-18",
			ToolCount:             2,
			ResourceCount:         0,
			ResourceTemplateCount: 0,
			PromptCount:           0,
			Evidence: models.MCPEvidence{
				URL: "http://127.0.0.1:8001/mcp",
				ResponseHeaders: map[string]string{
					"Content-Type": "application/json",
				},
				JSONRPC: models.JSONRPCSummary{
					RequestMethod: "initialize",
					StatusCode:    200,
					HasResult:     true,
					ResultKeys:    []string{"capabilities", "protocolVersion", "serverInfo"},
				},
				Fingerprint: models.FingerprintEvidence{
					Score:   0.85,
					Signals: []string{"protocol_version", "server_info.name"},
				},
				Auth: models.AuthEvidence{
					Status:  "no-auth",
					Reasons: []string{"initialize returned a valid MCP JSON-RPC result"},
				},
			},
			Tools: []models.MCPTool{
				{Name: "z-last", Description: "later"},
				{Name: "search", Description: "search docs"},
			},
		},
	}

	dir, err := WriteHTMLReports(results, t.TempDir(), []string{"127.0.0.1"}, "")
	if err != nil {
		t.Fatalf("WriteHTMLReports() error = %v", err)
	}

	zh := readFileForTest(t, filepath.Join(dir, "report_zh.html"))
	en := readFileForTest(t, filepath.Join(dir, "report_en.html"))

	for _, item := range []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "zh",
			content: zh,
			want:    []string{"AgentScan 扫描报告", "发现服务", "127.0.0.1:8001/mcp", "search docs", `data-sort="tools"`},
		},
		{
			name:    "en",
			content: en,
			want:    []string{"AgentScan Report", "Servers", "127.0.0.1:8001/mcp", "search docs", `data-sort="score"`, "Evidence", "server_info.name", "evidence-grid", "overflow-wrap: anywhere"},
		},
	} {
		for _, want := range item.want {
			if !strings.Contains(item.content, want) {
				t.Fatalf("%s report missing %q\n%s", item.name, want, item.content)
			}
		}
	}

	summary := readFileForTest(t, filepath.Join(dir, "summary.txt"))
	exposed := readFileForTest(t, filepath.Join(dir, "exposed.txt"))
	allFindings := readFileForTest(t, filepath.Join(dir, "all_findings.txt"))
	tools := readFileForTest(t, filepath.Join(dir, "tools.txt"))
	evidence := readFileForTest(t, filepath.Join(dir, "evidence.txt"))

	for _, item := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "summary", content: summary, want: "No auth: 1"},
		{name: "exposed", content: exposed, want: "http://127.0.0.1:8001/mcp"},
		{name: "all_findings", content: allFindings, want: "streamable-http"},
		{name: "tools", content: tools, want: "search docs"},
		{name: "evidence", content: evidence, want: "fingerprint: protocol_version, server_info.name"},
	} {
		if !strings.Contains(item.content, item.want) {
			t.Fatalf("%s missing %q\n%s", item.name, item.want, item.content)
		}
	}
}

func readFileForTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
