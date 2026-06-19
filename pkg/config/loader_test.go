package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile is a test helper that writes content to path, creating parent dirs.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// TestDefaultDictSet_DeepCopy verifies that mutating the returned DictSet does
// not pollute the package-level globals (Issue #6).
func TestDefaultDictSet_DeepCopy(t *testing.T) {
	ds1 := DefaultDictSet()
	ds2 := DefaultDictSet()

	// Append to ds1 slices — must not affect ds2 or the global vars.
	ds1.MCPPorts = append(ds1.MCPPorts, 99999)
	ds1.MCPEndpoints = append(ds1.MCPEndpoints, "/injected")
	ds1.MCPServerHints = append(ds1.MCPServerHints, "injected-hint")
	ds1.A2APorts = append(ds1.A2APorts, 99998)
	ds1.A2ACardPaths = append(ds1.A2ACardPaths, "/injected-a2a")

	// Mutate ds1 maps
	ds1.SSELegacyPaths["/injected-sse"] = true
	ds1.MCPAuthPaths["/injected-auth"] = true
	ds1.HTTPSPorts[12345] = true

	// ds2 must be pristine
	for _, p := range ds2.MCPPorts {
		if p == 99999 {
			t.Error("MCPPorts: ds1 mutation leaked into ds2")
		}
	}
	for _, e := range ds2.MCPEndpoints {
		if e == "/injected" {
			t.Error("MCPEndpoints: ds1 mutation leaked into ds2")
		}
	}
	if ds2.SSELegacyPaths["/injected-sse"] {
		t.Error("SSELegacyPaths: ds1 mutation leaked into ds2")
	}
	if ds2.MCPAuthPaths["/injected-auth"] {
		t.Error("MCPAuthPaths: ds1 mutation leaked into ds2")
	}
	if ds2.HTTPSPorts[12345] {
		t.Error("HTTPSPorts: ds1 mutation leaked into ds2")
	}

	// Package-level globals must also be untouched
	for _, p := range DefaultPorts {
		if p == 99999 {
			t.Error("DefaultPorts global was mutated")
		}
	}
}

// TestLoadDictSet_MissingDir returns an error when dir does not exist (Issue #2).
func TestLoadDictSet_MissingDir(t *testing.T) {
	_, err := LoadDictSet("/definitely/does/not/exist/agentscan-test-dict")
	if err == nil {
		t.Fatal("expected error for missing dir, got nil")
	}
}

// TestLoadDictSet_EmptyDir returns defaults (all files missing = silent fallback).
func TestLoadDictSet_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	ds, err := LoadDictSet(dir)
	if err != nil {
		t.Fatalf("empty dir should not error: %v", err)
	}
	if len(ds.MCPPorts) == 0 {
		t.Error("expected fallback MCPPorts, got empty")
	}
	if len(ds.A2APorts) == 0 {
		t.Error("expected fallback A2APorts, got empty")
	}
}

// TestLoadDictSet_HappyPath loads all dict files and verifies values are applied.
func TestLoadDictSet_HappyPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "mcp_ports.txt"), "8000\n8001\n# comment\n\n443\n")
	writeFile(t, filepath.Join(dir, "mcp_paths.txt"), "/mcp\n/sse\n")
	writeFile(t, filepath.Join(dir, "a2a_ports.txt"), "80\n443\n8080\n")
	writeFile(t, filepath.Join(dir, "a2a_paths.txt"), "/.well-known/agent-card.json\n")
	writeFile(t, filepath.Join(dir, "http_server_hints.txt"), "uvicorn\nFastAPI\n") // uppercase → lowercased
	writeFile(t, filepath.Join(dir, "https_ports.txt"), "443\n8443\n")

	ds, err := LoadDictSet(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// MCPPorts
	if len(ds.MCPPorts) != 3 {
		t.Errorf("MCPPorts: want 3 entries, got %d: %v", len(ds.MCPPorts), ds.MCPPorts)
	}

	// MCPEndpoints
	if len(ds.MCPEndpoints) != 2 {
		t.Errorf("MCPEndpoints: want 2, got %d", len(ds.MCPEndpoints))
	}

	// A2APorts
	if len(ds.A2APorts) != 3 {
		t.Errorf("A2APorts: want 3, got %d", len(ds.A2APorts))
	}

	// Hints are lowercased
	for _, h := range ds.MCPServerHints {
		if h != strings.ToLower(h) {
			t.Errorf("MCPServerHints: hint %q not lowercased", h)
		}
	}
	found := false
	for _, h := range ds.MCPServerHints {
		if h == "fastapi" {
			found = true
		}
	}
	if !found {
		t.Error("MCPServerHints: 'FastAPI' should be lowercased to 'fastapi'")
	}

	// HTTPSPorts
	if !ds.HTTPSPorts[443] || !ds.HTTPSPorts[8443] {
		t.Error("HTTPSPorts: 443 and 8443 should be present")
	}
}

// TestLoadDictSet_PartialFiles only some files present; others fall back to default.
func TestLoadDictSet_PartialFiles(t *testing.T) {
	dir := t.TempDir()
	// Only override MCP ports; everything else is absent.
	writeFile(t, filepath.Join(dir, "mcp_ports.txt"), "9999\n")

	ds, err := LoadDictSet(dir)
	if err != nil {
		t.Fatalf("partial dict dir should not error: %v", err)
	}

	// Custom MCP ports applied
	if len(ds.MCPPorts) != 1 || ds.MCPPorts[0] != 9999 {
		t.Errorf("MCPPorts: want [9999], got %v", ds.MCPPorts)
	}
	// A2A ports fall back to defaults (non-empty)
	if len(ds.A2APorts) == 0 {
		t.Error("A2APorts: expected fallback defaults, got empty")
	}
}

// TestLoadDictSet_DedupePaths verifies duplicate paths are removed (Issue #5).
func TestLoadDictSet_DedupePaths(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "mcp_paths.txt"), "/mcp\n/sse\n/mcp\n/sse\n")

	ds, err := LoadDictSet(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ds.MCPEndpoints) != 2 {
		t.Errorf("MCPEndpoints: want 2 after dedup, got %d: %v", len(ds.MCPEndpoints), ds.MCPEndpoints)
	}
}

// TestLoadDictSet_PathNormalization verifies leading slash is added (Issue #5).
func TestLoadDictSet_PathNormalization(t *testing.T) {
	dir := t.TempDir()
	// Paths without leading slash should get one added.
	writeFile(t, filepath.Join(dir, "mcp_paths.txt"), "mcp\nsse\n")

	ds, err := LoadDictSet(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, p := range ds.MCPEndpoints {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("MCPEndpoints: path %q missing leading /", p)
		}
	}
}

// TestLoadDictSet_InvalidPort verifies out-of-range ports are skipped with a
// warning (not returned as error) and valid ports are still loaded (Issue #4).
func TestLoadDictSet_InvalidPort(t *testing.T) {
	dir := t.TempDir()
	// Mix valid and invalid entries.
	writeFile(t, filepath.Join(dir, "mcp_ports.txt"), "8080\n99999\n0\nabc\n443\n")

	ds, err := LoadDictSet(dir)
	if err != nil {
		t.Fatalf("invalid lines should warn, not error: %v", err)
	}
	// Only 8080 and 443 are valid.
	if len(ds.MCPPorts) != 2 {
		t.Errorf("MCPPorts: want [8080, 443], got %v", ds.MCPPorts)
	}
	for _, p := range ds.MCPPorts {
		if p < 1 || p > 65535 {
			t.Errorf("MCPPorts: out-of-range port %d in result", p)
		}
	}
}

// TestLoadDictSet_EmptyString returns defaults without error.
func TestLoadDictSet_EmptyString(t *testing.T) {
	ds, err := LoadDictSet("")
	if err != nil {
		t.Fatalf("empty dir should not error: %v", err)
	}
	if len(ds.MCPPorts) == 0 {
		t.Error("expected non-empty MCPPorts from defaults")
	}
}
