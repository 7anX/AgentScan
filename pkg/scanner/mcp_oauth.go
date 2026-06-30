package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentscan/agentscan/pkg/config"
	"github.com/agentscan/agentscan/pkg/models"
)

// probeOAuthMeta discovers OAuth 2.0 metadata for an auth-required MCP endpoint.
//
// Two-stage discovery chain (both stages are public/unauthenticated):
//  1. RFC 9728 /.well-known/oauth-protected-resource → authorization_servers, scopes
//  2. RFC 8414 /.well-known/oauth-authorization-server → token_endpoint, registration_endpoint, …
//
// wwwAuthenticate is the value of the WWW-Authenticate response header from the MCP endpoint;
// when it contains resource_metadata="<url>", that URL is used directly instead of guessing.
// Returns nil if neither well-known endpoint responds with valid JSON.
func probeOAuthMeta(ctx context.Context, baseURL, endpoint, hostname, wwwAuthenticate string, timeoutMs int) *models.OAuthMeta {
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	client := buildHTTPClient(hostname, time.Duration(timeoutMs)*time.Millisecond)

	// Priority 1: use resource_metadata URL from WWW-Authenticate header (RFC 9728 §3 / MCP spec).
	// This is the most reliable path — the server tells us exactly where its metadata lives.
	var prMeta map[string]interface{}
	var discoveryURL string
	if rmURL := extractResourceMetadataURL(wwwAuthenticate); rmURL != "" {
		prMeta = fetchOAuthJSON(ctx, client, rmURL)
		if prMeta != nil {
			discoveryURL = rmURL
		}
	}

	// Priority 2: RFC 9728 URL with path insertion (e.g. /.well-known/oauth-protected-resource/mcp).
	if prMeta == nil {
		rfcURL := buildPRMetaURL(baseURL, endpoint)
		prMeta = fetchOAuthJSON(ctx, client, rfcURL)
		if prMeta != nil {
			discoveryURL = rfcURL
		}

		// Priority 3: simple host-level URL — common wrong implementation (VS Code, Claude Desktop, MCP Python SDK).
		if prMeta == nil {
			simpleURL := originWellKnown(baseURL, "oauth-protected-resource")
			if simpleURL != rfcURL {
				prMeta = fetchOAuthJSON(ctx, client, simpleURL)
				if prMeta != nil {
					discoveryURL = simpleURL
				}
			}
		}
	}

	if prMeta == nil {
		return nil
	}

	meta := &models.OAuthMeta{DiscoveryURL: discoveryURL}
	if v, ok := prMeta["resource"].(string); ok {
		meta.ResourceURL = v
	}
	meta.AuthorizationServers = oauthStringSlice(prMeta["authorization_servers"])
	meta.BearerMethodsSupported = oauthStringSlice(prMeta["bearer_methods_supported"])
	meta.ScopesSupported = oauthStringSlice(prMeta["scopes_supported"])

	// Follow to the first listed authorization server for RFC 8414 metadata.
	if len(meta.AuthorizationServers) > 0 {
		asMeta := fetchOAuthJSON(ctx, client, buildASMetaURL(meta.AuthorizationServers[0]))
		if asMeta != nil {
			if v, ok := asMeta["issuer"].(string); ok {
				meta.Issuer = v
			}
			if v, ok := asMeta["authorization_endpoint"].(string); ok {
				meta.AuthorizationEndpoint = v
			}
			if v, ok := asMeta["token_endpoint"].(string); ok {
				meta.TokenEndpoint = v
			}
			if v, ok := asMeta["registration_endpoint"].(string); ok {
				// registration_endpoint is CIMD (Nov 2025 MCP addition) or RFC 7591 DCR
				meta.RegistrationEndpoint = v
			}
			meta.GrantTypesSupported = oauthStringSlice(asMeta["grant_types_supported"])
		}
	}

	return meta
}

// buildPRMetaURL constructs the RFC 9728 §3 protected-resource metadata URL.
//
// The spec inserts /.well-known/oauth-protected-resource between the origin and the
// resource path.  Examples:
//   - baseURL="https://api.example.com"  endpoint="/mcp"
//     → "https://api.example.com/.well-known/oauth-protected-resource/mcp"
//   - baseURL="https://api.example.com"  endpoint="/" or ""
//     → "https://api.example.com/.well-known/oauth-protected-resource"
func buildPRMetaURL(baseURL, endpoint string) string {
	base := strings.TrimRight(baseURL, "/")
	path := strings.TrimRight(endpoint, "/")
	if path == "" || path == "/" {
		return base + "/.well-known/oauth-protected-resource"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + "/.well-known/oauth-protected-resource" + path
}

// originWellKnown returns the simple /.well-known/<name> URL at the origin of baseURL,
// stripping any path component.  Used as a fallback for implementations that skip the
// RFC 9728 path-insertion rule.
func originWellKnown(baseURL, name string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return strings.TrimRight(baseURL, "/") + "/.well-known/" + name
	}
	return u.Scheme + "://" + u.Host + "/.well-known/" + name
}

// buildASMetaURL constructs the RFC 8414 authorization-server metadata URL.
//
// If the issuer URL has a non-root path the path is appended (RFC 8414 §3):
//   - "https://auth.example.com"     → "https://auth.example.com/.well-known/oauth-authorization-server"
//   - "https://auth.example.com/v1"  → "https://auth.example.com/.well-known/oauth-authorization-server/v1"
func buildASMetaURL(issuerURL string) string {
	u, err := url.Parse(strings.TrimRight(issuerURL, "/"))
	if err != nil {
		return strings.TrimRight(issuerURL, "/") + "/.well-known/oauth-authorization-server"
	}
	if u.Path == "" || u.Path == "/" {
		return u.Scheme + "://" + u.Host + "/.well-known/oauth-authorization-server"
	}
	return u.Scheme + "://" + u.Host + "/.well-known/oauth-authorization-server" + u.Path
}

// fetchOAuthJSON performs a GET and decodes the JSON response.
// Returns nil on any error: non-200 status, non-JSON content-type, timeout, parse failure.
func fetchOAuthJSON(ctx context.Context, client *http.Client, rawURL string) map[string]interface{} {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", config.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}

	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil
	}
	return out
}

func oauthStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// extractResourceMetadataURL extracts the resource_metadata URL from a WWW-Authenticate header.
// Handles both quoted and unquoted forms:
//   Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"
//   Bearer resource_metadata=https://example.com/.well-known/oauth-protected-resource/mcp
func extractResourceMetadataURL(wwwAuth string) string {
	const key = "resource_metadata="
	idx := strings.Index(wwwAuth, key)
	if idx < 0 {
		return ""
	}
	rest := wwwAuth[idx+len(key):]
	if strings.HasPrefix(rest, `"`) {
		// Quoted value: find closing quote
		end := strings.Index(rest[1:], `"`)
		if end < 0 {
			return ""
		}
		return rest[1 : end+1]
	}
	// Unquoted value: ends at comma, space, or end of string
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		return rest
	}
	return rest[:end]
}
