package mcpwire

import "encoding/json"

var (
	initBodyStreamable = mustBuildInitializeRequest("2025-06-18")
	initBodyLegacy     = mustBuildInitializeRequest("2024-11-05")
	initBodyInvalid    = mustBuildInitializeRequest("9999-99-99")
)

func mustBuildInitializeRequest(version string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": version,
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "mcp-client",
				"version": "1.0.0",
			},
		},
	})
	return b
}

// InitializeRequest returns a pre-built MCP initialize request body when possible.
func InitializeRequest(version string) []byte {
	switch version {
	case "2025-06-18":
		return initBodyStreamable
	case "2024-11-05":
		return initBodyLegacy
	case "9999-99-99":
		return initBodyInvalid
	default:
		return mustBuildInitializeRequest(version)
	}
}
