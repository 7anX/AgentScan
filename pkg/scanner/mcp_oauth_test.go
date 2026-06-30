package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── URL builder tests ────────────────────────────────────────────────────────

func TestBuildPRMetaURL(t *testing.T) {
	cases := []struct {
		baseURL  string
		endpoint string
		want     string
	}{
		// Standard: insert between origin and path
		{"https://api.example.com", "/mcp", "https://api.example.com/.well-known/oauth-protected-resource/mcp"},
		{"https://api.example.com", "/api/v1/mcp", "https://api.example.com/.well-known/oauth-protected-resource/api/v1/mcp"},
		// Root or empty endpoint: no suffix
		{"https://api.example.com", "/", "https://api.example.com/.well-known/oauth-protected-resource"},
		{"https://api.example.com", "", "https://api.example.com/.well-known/oauth-protected-resource"},
		// Trailing slash on baseURL stripped
		{"https://api.example.com/", "/mcp", "https://api.example.com/.well-known/oauth-protected-resource/mcp"},
		// Endpoint without leading slash
		{"https://api.example.com", "mcp", "https://api.example.com/.well-known/oauth-protected-resource/mcp"},
	}
	for _, c := range cases {
		got := buildPRMetaURL(c.baseURL, c.endpoint)
		if got != c.want {
			t.Errorf("buildPRMetaURL(%q, %q)\n  got:  %q\n  want: %q", c.baseURL, c.endpoint, got, c.want)
		}
	}
}

func TestOriginWellKnown(t *testing.T) {
	cases := []struct {
		baseURL string
		name    string
		want    string
	}{
		{"https://api.example.com/mcp", "oauth-protected-resource", "https://api.example.com/.well-known/oauth-protected-resource"},
		{"http://10.0.0.1:8080/some/path", "oauth-protected-resource", "http://10.0.0.1:8080/.well-known/oauth-protected-resource"},
		{"https://api.example.com", "oauth-protected-resource", "https://api.example.com/.well-known/oauth-protected-resource"},
	}
	for _, c := range cases {
		got := originWellKnown(c.baseURL, c.name)
		if got != c.want {
			t.Errorf("originWellKnown(%q, %q) = %q, want %q", c.baseURL, c.name, got, c.want)
		}
	}
}

func TestBuildASMetaURL(t *testing.T) {
	cases := []struct {
		issuerURL string
		want      string
	}{
		{"https://auth.example.com", "https://auth.example.com/.well-known/oauth-authorization-server"},
		{"https://auth.example.com/", "https://auth.example.com/.well-known/oauth-authorization-server"},
		// Issuer with path suffix (RFC 8414 §3)
		{"https://auth.example.com/v1", "https://auth.example.com/.well-known/oauth-authorization-server/v1"},
	}
	for _, c := range cases {
		got := buildASMetaURL(c.issuerURL)
		if got != c.want {
			t.Errorf("buildASMetaURL(%q) = %q, want %q", c.issuerURL, got, c.want)
		}
	}
}

// ── End-to-end mock server test ──────────────────────────────────────────────

func TestProbeOAuthMeta_FullChain(t *testing.T) {
	// Authorization server metadata served at /.well-known/oauth-authorization-server
	asMux := http.NewServeMux()
	asMux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 "https://auth.test",
			"authorization_endpoint": "https://auth.test/authorize",
			"token_endpoint":         "https://auth.test/token",
			"registration_endpoint":  "https://auth.test/register",
			"grant_types_supported":  []string{"authorization_code", "client_credentials"},
		})
	})
	asServer := httptest.NewServer(asMux)
	defer asServer.Close()

	// Protected resource metadata served at /.well-known/oauth-protected-resource/mcp
	prMux := http.NewServeMux()
	prMux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resource":                 "http://mcp.test/mcp",
			"authorization_servers":    []string{asServer.URL},
			"bearer_methods_supported": []string{"header"},
			"scopes_supported":         []string{"mcp:read", "mcp:write"},
		})
	})
	prServer := httptest.NewServer(prMux)
	defer prServer.Close()

	meta := probeOAuthMeta(context.Background(), prServer.URL, "/mcp", "", "", 5000)
	if meta == nil {
		t.Fatal("expected OAuthMeta, got nil")
	}

	if meta.ResourceURL != "http://mcp.test/mcp" {
		t.Errorf("ResourceURL = %q", meta.ResourceURL)
	}
	if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != asServer.URL {
		t.Errorf("AuthorizationServers = %v", meta.AuthorizationServers)
	}
	if meta.TokenEndpoint != "https://auth.test/token" {
		t.Errorf("TokenEndpoint = %q", meta.TokenEndpoint)
	}
	if meta.RegistrationEndpoint != "https://auth.test/register" {
		t.Errorf("RegistrationEndpoint = %q", meta.RegistrationEndpoint)
	}
	if len(meta.GrantTypesSupported) != 2 {
		t.Errorf("GrantTypesSupported = %v", meta.GrantTypesSupported)
	}
	if len(meta.ScopesSupported) != 2 {
		t.Errorf("ScopesSupported = %v", meta.ScopesSupported)
	}
}

func TestProbeOAuthMeta_WWWAuthenticateHeader(t *testing.T) {
	// Server exposes protected resource metadata at a custom URL
	// (as specified in WWW-Authenticate header, not guessable from base URL)
	prMux := http.NewServeMux()
	prMux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resource":              "https://mcp.example.com/mcp",
			"authorization_servers": []string{"https://auth.example.com"},
			"scopes_supported":      []string{"data:read_write"},
		})
	})
	srv := httptest.NewServer(prMux)
	defer srv.Close()

	// Simulate: WWW-Authenticate tells us exactly where the metadata is
	wwwAuth := `Bearer error="invalid_request", resource_metadata="` + srv.URL + `/.well-known/oauth-protected-resource/mcp"`
	// Probe with wrong baseURL but correct wwwAuthenticate header
	meta := probeOAuthMeta(context.Background(), "https://totally-wrong-url.example.com", "/mcp", "", wwwAuth, 5000)
	if meta == nil {
		t.Fatal("expected OAuthMeta via WWW-Authenticate URL, got nil")
	}
	if meta.ResourceURL != "https://mcp.example.com/mcp" {
		t.Errorf("ResourceURL = %q", meta.ResourceURL)
	}
}

func TestProbeOAuthMeta_FallbackToSimpleURL(t *testing.T) {
	// Server only responds to simple host-level URL (common wrong implementation)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"resource":              "http://mcp.test/mcp",
			"authorization_servers": []string{"https://auth.example.com"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Endpoint is "/mcp", so RFC URL would be /.well-known/oauth-protected-resource/mcp (404)
	// fallback should hit /.well-known/oauth-protected-resource (200)
	meta := probeOAuthMeta(context.Background(), srv.URL, "/mcp", "", "", 5000)
	if meta == nil {
		t.Fatal("expected OAuthMeta via fallback URL, got nil")
	}
	if meta.ResourceURL != "http://mcp.test/mcp" {
		t.Errorf("ResourceURL = %q", meta.ResourceURL)
	}
}

func TestProbeOAuthMeta_NoEndpoint(t *testing.T) {
	// Server returns 404 for both URLs
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	meta := probeOAuthMeta(context.Background(), srv.URL, "/mcp", "", "", 5000)
	if meta != nil {
		t.Errorf("expected nil, got %+v", meta)
	}
}

func TestProbeOAuthMeta_NonJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>not json</html>"))
	}))
	defer srv.Close()

	meta := probeOAuthMeta(context.Background(), srv.URL, "/mcp", "", "", 5000)
	if meta != nil {
		t.Errorf("expected nil for non-JSON, got %+v", meta)
	}
}

// ── fetchOAuthJSON edge cases ────────────────────────────────────────────────

func TestFetchOAuthJSON_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()

	client := &http.Client{}
	got := fetchOAuthJSON(context.Background(), client, srv.URL+"/test")
	if got != nil {
		t.Errorf("expected nil for 401, got %v", got)
	}
}

func TestOAuthStringSlice(t *testing.T) {
	got := oauthStringSlice([]interface{}{"a", "b", 42, "c"})
	if len(got) != 3 || strings.Join(got, ",") != "a,b,c" {
		t.Errorf("oauthStringSlice got %v", got)
	}
	if oauthStringSlice(nil) != nil {
		t.Error("nil input should return nil")
	}
}

func TestExtractResourceMetadataURL(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// GitHub Copilot style
		{
			`Bearer error="invalid_request", error_description="No access token", resource_metadata="https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/"`,
			"https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/",
		},
		// Todoist style
		{
			`Bearer resource_metadata="https://ai.todoist.net/.well-known/oauth-protected-resource/mcp"`,
			"https://ai.todoist.net/.well-known/oauth-protected-resource/mcp",
		},
		// Unquoted form
		{
			`Bearer resource_metadata=https://example.com/.well-known/oauth-protected-resource`,
			"https://example.com/.well-known/oauth-protected-resource",
		},
		// Not present
		{`Bearer realm="mcp"`, ""},
		// Empty
		{"", ""},
	}
	for _, c := range cases {
		got := extractResourceMetadataURL(c.input)
		if got != c.want {
			t.Errorf("extractResourceMetadataURL(%q)\n  got:  %q\n  want: %q", c.input, got, c.want)
		}
	}
}
