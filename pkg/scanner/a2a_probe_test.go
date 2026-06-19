package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentscan/agentscan/pkg/models"
)

func TestProbeA2ALegacyAgentJSONNoAuthJSONRPC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent.json":
			writeJSON(t, w, map[string]interface{}{
				"name":        "system-admin-agent",
				"description": "System administration agent",
				"url":         "/a2a",
				"capabilities": map[string]interface{}{
					"streaming":         false,
					"pushNotifications": false,
				},
				"skills": []map[string]interface{}{
					{"id": "schedule_system_commands", "name": "schedule_system_commands", "description": "Schedule system commands"},
				},
			})
		case "/a2a":
			w.WriteHeader(http.StatusNotFound)
			writeJSON(t, w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"error": map[string]interface{}{
					"code":    -32601,
					"message": "Method not found",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, false, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() returned nil")
	}
	if got.Profile != models.A2AProfileLegacyAgentJSON {
		t.Fatalf("profile = %q, want %q", got.Profile, models.A2AProfileLegacyAgentJSON)
	}
	if got.ExposureStatus != models.A2AExposureJSONRPCNoAuth {
		t.Fatalf("exposure status = %q, want %q", got.ExposureStatus, models.A2AExposureJSONRPCNoAuth)
	}
	if !got.NoAuth {
		t.Fatal("NoAuth = false, want true")
	}
	if len(got.Interfaces) != 1 || got.Interfaces[0].Status != models.A2AStatusNoAuthJSONRPCReachable {
		t.Fatalf("interfaces = %#v, want no-auth JSON-RPC reachable", got.Interfaces)
	}
	if !containsA2ATestString(got.ExposureSignals, "system_admin_skill_names") {
		t.Fatalf("signals = %#v, want system_admin_skill_names", got.ExposureSignals)
	}
}

func TestProbeA2AEndpointDisabledIsSeparateStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent.json":
			writeJSON(t, w, map[string]interface{}{
				"name":        "OmniRoute AI Gateway",
				"description": "Routing gateway",
				"url":         "http://localhost:20128/a2a",
				"capabilities": map[string]interface{}{
					"streaming":         true,
					"pushNotifications": false,
				},
				"skills": []map[string]interface{}{
					{"id": "smart-routing", "name": "Smart Request Routing"},
				},
			})
		case "/a2a":
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(t, w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"error": map[string]interface{}{
					"code":    -32000,
					"message": "A2A endpoint is disabled. Enable it from the Endpoints page.",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, false, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() returned nil")
	}
	if got.ExposureStatus != models.A2AExposureDisabled {
		t.Fatalf("exposure status = %q, want %q", got.ExposureStatus, models.A2AExposureDisabled)
	}
	if got.NoAuth {
		t.Fatal("NoAuth = true, want false for disabled endpoint")
	}
	if !got.EndpointDisabled {
		t.Fatal("EndpointDisabled = false, want true")
	}
	if len(got.Interfaces) != 1 || !got.Interfaces[0].PrivateHostAdvertised {
		t.Fatalf("interfaces = %#v, want private host advertised and rebased", got.Interfaces)
	}
}

func TestProbeA2ARejectsAlternateAgentDiscoverySchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/agent.json" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]interface{}{
			"$schema":     "https://agentprotocol.ai/schema/agent.json",
			"name":        "Not A2A",
			"description": "Agent Protocol document",
			"capabilities": map[string]interface{}{
				"actions": []interface{}{},
			},
		})
	}))
	defer srv.Close()

	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, true, nil)
	if got != nil {
		t.Fatalf("ProbeA2AWithHostname() = %#v, want nil for alternate schema", got)
	}
}

func TestProbeA2AExtendedCardNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			writeJSON(t, w, map[string]interface{}{
				"name":            "Docs by LangChain",
				"description":     "Documentation agent",
				"protocolVersion": "1.0",
				"capabilities": map[string]interface{}{
					"streaming":         false,
					"extendedAgentCard": true,
				},
				"skills": []map[string]interface{}{
					{"id": "doc-search", "name": "Document Search"},
				},
				"supportedInterfaces": []map[string]interface{}{
					{"protocolBinding": "JSONRPC", "url": "/a2a"},
				},
			})
		case "/a2a":
			// GetExtendedAgentCard returns result without auth → extended_card_no_auth
			// AgentScanProbe → method not found
			var req map[string]interface{}
			json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
			method, _ := req["method"].(string)
			if method == "GetExtendedAgentCard" {
				writeJSON(t, w, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"result": map[string]interface{}{
						"name":  "Extended LangChain Card",
						"skills": []interface{}{},
					},
				})
				return
			}
			writeJSON(t, w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"error": map[string]interface{}{
					"code":    -32601,
					"message": "Method not found",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, false, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() returned nil")
	}
	if got.Profile != models.A2AProfileAgentCard {
		t.Fatalf("profile = %q, want %q", got.Profile, models.A2AProfileAgentCard)
	}
	if !containsA2ATestString(got.ExposureSignals, "extended_card_no_auth") {
		t.Fatalf("ExposureSignals = %v, want extended_card_no_auth", got.ExposureSignals)
	}
}

func TestProbeA2ADeclaredAuthDetection(t *testing.T) {
	tests := []struct {
		name         string
		card         map[string]interface{}
		wantDeclared string
	}{
		{
			name: "no_security_fields",
			card: map[string]interface{}{
				"name":        "Open Agent",
				"description": "No auth",
				"url":         "/a2a",
				"capabilities": map[string]interface{}{"streaming": false},
				"skills":      []interface{}{map[string]interface{}{"id": "x", "name": "x"}},
			},
			wantDeclared: "declared_none",
		},
		{
			name: "security_array_present",
			card: map[string]interface{}{
				"name":        "Secure Agent",
				"description": "Requires auth",
				"url":         "/a2a",
				"capabilities": map[string]interface{}{"streaming": false},
				"skills":      []interface{}{map[string]interface{}{"id": "x", "name": "x"}},
				"securitySchemes": map[string]interface{}{
					"bearer": map[string]interface{}{"type": "http", "scheme": "bearer"},
				},
				"security": []interface{}{
					map[string]interface{}{"bearer": []interface{}{}},
				},
			},
			wantDeclared: "declared_required",
		},
		{
			name: "schemes_only_no_requirements",
			card: map[string]interface{}{
				"name":        "Ambiguous Agent",
				"description": "Has schemes but no requirements",
				"url":         "/a2a",
				"capabilities": map[string]interface{}{"streaming": false},
				"skills":      []interface{}{map[string]interface{}{"id": "x", "name": "x"}},
				"securitySchemes": map[string]interface{}{
					"bearer": map[string]interface{}{"type": "http"},
				},
			},
			wantDeclared: "declared_ambiguous",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/agent.json" {
					writeJSON(t, w, tt.card)
					return
				}
				// /a2a → method not found
				writeJSON(t, w, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"error":   map[string]interface{}{"code": -32601, "message": "Method not found"},
				})
			}))
			defer srv.Close()

			got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, false, nil)
			if got == nil {
				t.Fatal("ProbeA2AWithHostname() returned nil")
			}
			if got.Evidence.Auth.Declared != tt.wantDeclared {
				t.Fatalf("declared auth = %q, want %q", got.Evidence.Auth.Declared, tt.wantDeclared)
			}
		})
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("json encode: %v", err)
	}
}

func containsA2ATestString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
