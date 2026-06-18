package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestBuildProbeEndpointsExpandsMountPrefix(t *testing.T) {
	got := buildProbeEndpoints("/9da4ht4y/")
	wantPrefix := []string{
		"/9da4ht4y/",
		"/9da4ht4y/mcp",
		"/9da4ht4y/sse",
	}
	if len(got) < len(wantPrefix) || !reflect.DeepEqual(got[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("buildProbeEndpoints prefix = %v, want prefix %v", got[:min(len(got), len(wantPrefix))], wantPrefix)
	}
}

func TestBuildProbeEndpointsDoesNotExpandKnownEndpoint(t *testing.T) {
	got := buildProbeEndpoints("/mcp")
	mcpSSECount := 0
	for _, ep := range got {
		if ep == "/mcp/mcp" {
			t.Fatalf("buildProbeEndpoints(/mcp) unexpectedly expanded concrete endpoint: %v", got)
		}
		if ep == "/mcp/sse" {
			mcpSSECount++
		}
	}
	if got[0] != "/mcp" {
		t.Fatalf("first endpoint = %q, want /mcp", got[0])
	}
	if mcpSSECount != 1 {
		t.Fatalf("/mcp/sse count = %d, want 1 in %v", mcpSSECount, got)
	}
}

func TestProbeMCPWithHostnameFindsSSEUnderMountPrefix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/prefix/sse" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"unauthorized"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	got := ProbeMCPWithHostname(context.Background(), server.URL, "", "/prefix/", 1000)
	if got == nil {
		t.Fatal("ProbeMCPWithHostname() returned nil, want auth-required SSE result")
	}
	if got.Endpoint != "/prefix/sse" {
		t.Fatalf("Endpoint = %q, want /prefix/sse", got.Endpoint)
	}
	if !got.AuthRequired {
		t.Fatalf("AuthRequired = false, want true: %#v", got)
	}
}

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
