package target

import "testing"

func TestParseURLWithoutExplicitPortUsesSchemeDefault(t *testing.T) {
	targets, err := Parse("http://127.0.0.1", []int{80, 443})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Port != 80 {
		t.Fatalf("Port = %d, want 80", targets[0].Port)
	}
	if targets[0].Proto != "http" {
		t.Fatalf("Proto = %q, want %q", targets[0].Proto, "http")
	}
}

func TestParseHTTPSURLWithoutExplicitPort(t *testing.T) {
	targets, err := Parse("https://127.0.0.1", []int{80, 443})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Port != 443 {
		t.Fatalf("Port = %d, want 443", targets[0].Port)
	}
	if targets[0].Proto != "https" {
		t.Fatalf("Proto = %q, want %q", targets[0].Proto, "https")
	}
}

func TestParseURLWithExplicitPortKeepsSchemeAndPath(t *testing.T) {
	targets, err := Parse("http://127.0.0.1:8882/9da4ht4y/sse", []int{80, 443})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	target := targets[0]
	if target.Port != 8882 {
		t.Fatalf("Port = %d, want 8882", target.Port)
	}
	if target.Proto != "http" {
		t.Fatalf("Proto = %q, want http", target.Proto)
	}
	if target.URLPath != "/9da4ht4y/sse" {
		t.Fatalf("URLPath = %q, want /9da4ht4y/sse", target.URLPath)
	}
}
