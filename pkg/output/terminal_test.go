package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/agentscan/agentscan/pkg/models"
)

func TestFprintServerFormatsNoAuthFinding(t *testing.T) {
	server := &models.MCPServer{
		IP:                    "47.109.39.227",
		Port:                  8001,
		Endpoint:              "/mcp",
		Transport:             models.TransportHTTPSSELegacy,
		ProtocolVersion:       "2024-11-05",
		NoAuth:                true,
		ServerName:            "SQLBot MCP Server",
		ServerVersion:         "SQLBot MCP Server",
		ToolCount:             2,
		ResourceCount:         0,
		ResourceTemplateCount: 0,
		PromptCount:           0,
	}

	var buf bytes.Buffer
	FprintServer(&buf, server, true)
	got := buf.String()

	assertContains(t, got, "[MCP] 47.109.39.227:8001/mcp")
	assertContains(t, got, "sse-legacy")
	assertContains(t, got, "2024-11-05")
	assertContains(t, got, "no-auth")
	assertContains(t, got, "server   SQLBot MCP Server")
	assertContains(t, got, "exposed  tools=2  resources=0  templates=0  prompts=0")
	assertNotContains(t, got, `server="SQLBot MCP Server/SQLBot MCP Server"`)
}

func TestFprintServerFormatsAuthRequiredFinding(t *testing.T) {
	server := &models.MCPServer{
		IP:           "116.62.152.243",
		Port:         8001,
		Endpoint:     "/mcp",
		Transport:    models.TransportStreamableHTTP,
		AuthRequired: true,
	}

	var buf bytes.Buffer
	FprintServer(&buf, server, true)
	got := buf.String()

	assertContains(t, got, "116.62.152.243:8001/mcp")
	assertContains(t, got, "streamable-http")
	assertContains(t, got, "unknown")
	assertContains(t, got, "auth-required")
	assertContains(t, got, "tools/resources unavailable until authenticated")
	assertNotContains(t, got, "v=")
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("expected output to contain %q\noutput:\n%s", want, got)
	}
}

func assertNotContains(t *testing.T, got, want string) {
	t.Helper()
	if strings.Contains(got, want) {
		t.Fatalf("expected output not to contain %q\noutput:\n%s", want, got)
	}
}
