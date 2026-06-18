package scanner

import (
	"testing"
	"time"

	"github.com/agentscan/agentscan/pkg/models"
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
