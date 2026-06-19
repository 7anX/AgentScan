package scanner

import (
	"testing"
	"time"

	"github.com/agentscan/agentscan/pkg/models"
	"github.com/agentscan/agentscan/pkg/target"
)

func TestProgressPercentDoesNotRoundIncompleteScanTo100(t *testing.T) {
	if got := progressPercent(456, 457); got != 99 {
		t.Fatalf("progressPercent(456, 457) = %d, want 99", got)
	}
	if got := progressPercent(457, 457); got != 100 {
		t.Fatalf("progressPercent(457, 457) = %d, want 100", got)
	}
}

func TestCandidateTimeoutDurationIsBounded(t *testing.T) {
	if got := candidateTimeoutDuration(models.ScanConfig{TimeoutMCPMs: 1000, TimeoutHTTPMs: 1000}); got != 8*time.Second {
		t.Fatalf("small timeout = %v, want 8s", got)
	}
	if got := candidateTimeoutDuration(models.ScanConfig{TimeoutMCPMs: 40000, TimeoutHTTPMs: 20000}); got != 45*time.Second {
		t.Fatalf("large timeout = %v, want 45s", got)
	}
}

func TestSlowCandidateThresholdIsBounded(t *testing.T) {
	if got := slowCandidateThreshold(models.ScanConfig{TimeoutMCPMs: 1000}); got != 5*time.Second {
		t.Fatalf("small threshold = %v, want 5s", got)
	}
	if got := slowCandidateThreshold(models.ScanConfig{TimeoutMCPMs: 30000}); got != 15*time.Second {
		t.Fatalf("large threshold = %v, want 15s", got)
	}
}

func TestDedupeTargetsKeepsHostnameAndProtoDistinct(t *testing.T) {
	input := []target.Target{
		{IP: "203.0.113.10", Port: 443, Hostname: "a.example", URLPath: "/mcp", Proto: "https"},
		{IP: "203.0.113.10", Port: 443, Hostname: "b.example", URLPath: "/mcp", Proto: "https"},
		{IP: "203.0.113.10", Port: 443, Hostname: "a.example", URLPath: "/mcp", Proto: "http"},
		{IP: "203.0.113.10", Port: 443, Hostname: "a.example", URLPath: "/mcp", Proto: "https"},
	}

	got, dupCount := dedupeTargets(input)
	if dupCount != 1 {
		t.Fatalf("dupCount = %d, want 1", dupCount)
	}
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3: %#v", len(got), got)
	}
}
