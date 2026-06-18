package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTryHTTPSSELegacyRejectsEmptyJSONRPCResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("event: endpoint\ndata: /message?session_id=test\n"))
		case "/message":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"result":  nil,
				"error":   nil,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := buildHTTPClient("", time.Second)
	got := tryHTTPSSELegacy(context.Background(), client, server.URL, "/sse", time.Second)
	if got != nil {
		t.Fatalf("tryHTTPSSELegacy() returned %#v, want nil for empty JSON-RPC response", got)
	}
}

func TestTryHTTPSSELegacyAcceptsMCPInitializeResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("event: endpoint\ndata: /message?session_id=test\n"))
		case "/message":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"result": map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"capabilities": map[string]interface{}{
						"tools": map[string]interface{}{},
					},
					"serverInfo": map[string]interface{}{
						"name":    "demo",
						"version": "1.0.0",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := buildHTTPClient("", time.Second)
	got := tryHTTPSSELegacy(context.Background(), client, server.URL, "/sse", time.Second)
	if got == nil {
		t.Fatal("tryHTTPSSELegacy() returned nil, want MCP result")
	}
	if got.ServerName != "demo" || got.ProtocolVersion != "2024-11-05" {
		t.Fatalf("unexpected result: %#v", got)
	}
}
