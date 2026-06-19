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
	exposed := readFileForTest(t, filepath.Join(dir, "mcp_no_auth.txt"))
	allFindings := readFileForTest(t, filepath.Join(dir, "mcp_findings.txt"))
	tools := readFileForTest(t, filepath.Join(dir, "mcp_tools.txt"))
	evidence := readFileForTest(t, filepath.Join(dir, "mcp_evidence.txt"))

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

func TestWriteUnifiedHTMLReportsContainsBothProtocols(t *testing.T) {
	mcpResults := []*models.MCPServer{
		{
			IP: "127.0.0.1", Port: 8001, URL: "http://127.0.0.1:8001",
			Endpoint: "/mcp", Transport: models.TransportStreamableHTTP,
			FingerprintScore: 0.85, NoAuth: true, ServerName: "TestMCP", ToolCount: 3,
			Evidence: models.MCPEvidence{
				URL:         "http://127.0.0.1:8001/mcp",
				Fingerprint: models.FingerprintEvidence{Score: 0.85, Signals: []string{"protocol_version"}},
				Auth:        models.AuthEvidence{Status: "no-auth", Reasons: []string{"init ok"}},
				JSONRPC:     models.JSONRPCSummary{RequestMethod: "initialize", StatusCode: 200},
			},
		},
	}
	a2aResults := []*models.A2AServer{
		{
			IP: "127.0.0.2", Port: 443, URL: "https://127.0.0.2",
			CardURL:        "https://127.0.0.2/.well-known/agent-card.json",
			CardPath:       "/.well-known/agent-card.json",
			Profile:        models.A2AProfileAgentCard,
			ExposureStatus: models.A2AExposureJSONRPCNoAuth,
			A2AConfirmed:   true, FingerprintScore: 0.90, NoAuth: true,
			AgentName: "TestA2AAgent", SkillCount: 2,
			Skills: []models.A2ASkill{{ID: "s1", Name: "Search"}},
			Evidence: models.A2AEvidence{
				Auth: models.A2AAuthEvidence{Declared: "declared_none", Status: "confirmed_a2a_jsonrpc_no_auth"},
			},
		},
	}
	llmResults := []*models.LLMServer{
		{
			IP: "127.0.0.3", Port: 11434, URL: "http://127.0.0.3:11434",
			Framework: "ollama", AuthStatus: "open",
			FingerprintScore: 0.95, ModelCount: 1,
			Models: []models.LLMModel{{ID: "llama3"}},
			Evidence: models.LLMEvidence{
				MatchedEndpoints: []models.LLMEndpointEvidence{{Method: "GET", Path: "/api/tags", StatusCode: 200, Matched: true}},
			},
		},
	}

	dir, err := WriteUnifiedHTMLReports(mcpResults, a2aResults, llmResults, t.TempDir(), nil, "")
	if err != nil {
		t.Fatalf("WriteUnifiedHTMLReports() error = %v", err)
	}

	en := readFileForTest(t, filepath.Join(dir, "report_en.html"))

	for _, want := range []string{
		"badge-mcp", "badge-a2a", // both protocol badges
		"badge-llm",                     // LLM protocol badge
		"TestMCP",                       // MCP server name
		"TestA2AAgent",                  // A2A agent name
		"ollama",                        // LLM framework
		"llama3",                        // LLM model
		"tab-mcp", "tab-a2a", "tab-llm", // tab panel IDs
		"confirmed_a2a_jsonrpc_no_auth", // A2A status
		"127.0.0.1:8001/mcp",            // MCP target
		"127.0.0.3:11434",               // LLM target
	} {
		if !strings.Contains(en, want) {
			t.Fatalf("unified report missing %q", want)
		}
	}

	// Text files from both protocols should exist
	for _, name := range []string{"summary.txt", "mcp_findings.txt", "mcp_tools.txt", "a2a_no_auth.txt", "a2a_skills.txt", "llm_findings.txt", "llm_models.txt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing report file %s: %v", name, err)
		}
	}
}
