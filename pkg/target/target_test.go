package target

import "testing"

func TestParseURLWithoutExplicitPortDoesNotForceSchemeOnAllPorts(t *testing.T) {
	targets, err := Parse("http://127.0.0.1", []int{80, 443})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2", len(targets))
	}
	for _, target := range targets {
		if target.Proto != "" {
			t.Fatalf("target %+v forced proto %q, want empty", target, target.Proto)
		}
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
