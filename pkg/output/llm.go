package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/agentscan/agentscan/pkg/models"
)

// ── Terminal output ─────────────────────────────────────────────────────────

// PrintLLMServer prints one LLM finding as a compact terminal block.
func PrintLLMServer(s *models.LLMServer, noColor bool) {
	FprintLLMServer(os.Stdout, s, noColor)
}

// FprintLLMServer writes one LLM finding to a writer.
func FprintLLMServer(w io.Writer, s *models.LLMServer, noColor bool) {
	bold, reset, green, muted := "", "", "", ""
	if !noColor && !NoColorEnabled() {
		bold = "\033[1m"
		reset = "\033[0m"
		green = "\033[32m"
		muted = "\033[90m"
	}

	target := fmt.Sprintf("%s:%d", s.IP, s.Port)
	if s.Hostname != "" && s.Hostname != s.IP {
		target = fmt.Sprintf("%s:%d", s.Hostname, s.Port)
	}

	// Auth status color: open=green(bold), auth_required=yellow(bold)
	authColor := ""
	if !noColor && !NoColorEnabled() {
		switch s.AuthStatus {
		case "open":
			authColor = "\033[32m\033[1m"
		case "auth_required":
			authColor = "\033[33m\033[1m"
		}
	}

	fmt.Fprintf(w, "%s[LLM]%s %-25s %-15s %s%-14s%s models=%d  score=%.2f\n",
		bold, reset,
		target,
		s.Framework,
		authColor, s.AuthStatus, reset,
		s.ModelCount,
		s.FingerprintScore,
	)
	if s.FrameworkVersion != "" {
		fmt.Fprintf(w, "      version  %s\n", s.FrameworkVersion)
	}
	if s.ModelCount > 0 && s.ModelCount <= 10 {
		names := make([]string, 0, len(s.Models))
		for _, m := range s.Models {
			names = append(names, m.ID)
		}
		fmt.Fprintf(w, "      models   %s\n", strings.Join(names, ", "))
	}
	// List matched endpoints
	for _, ep := range s.Evidence.MatchedEndpoints {
		if !ep.Matched {
			continue
		}
		fieldsStr := ""
		if ep.ResponseFieldCount > 0 {
			fieldsStr = fmt.Sprintf(" fields=%d", ep.ResponseFieldCount)
		}
		fmt.Fprintf(w, "      %shit%s      %s %-20s → %s%d%s %s(%.0fms)%s%s\n",
			green, reset,
			ep.Method, ep.Path,
			bold, ep.StatusCode, reset,
			muted, ep.ResponseMs, reset,
			fieldsStr)
	}
	fmt.Fprintln(w)
}

// PrintLLMSummary prints the final LLM scan summary.
func PrintLLMSummary(results []*models.LLMServer, noColor bool) {
	FprintLLMSummary(os.Stdout, results, noColor)
}

// FprintLLMSummary writes the LLM scan summary to a writer.
func FprintLLMSummary(w io.Writer, results []*models.LLMServer, noColor bool) {
	bold, reset, red := "", "", ""
	if !noColor && !NoColorEnabled() {
		bold = "\033[1m"
		reset = "\033[0m"
		red = "\033[31m"
	}

	summary := summarizeLLMResults(results)

	// open count — red if > 0
	openStr := fmt.Sprintf("open=%d", summary.Open)
	if summary.Open > 0 {
		openStr = fmt.Sprintf("%sopen=%d%s", red, summary.Open, reset)
	}

	fmt.Fprintf(w, "%sSummary%s  LLM=%d  %s  auth-req=%d  models=%d\n",
		bold, reset, summary.Total, openStr, summary.AuthRequired, summary.TotalModels)
}

// ── JSON output ─────────────────────────────────────────────────────────────

// LLMJSONReport is the top-level JSON report structure.
type LLMJSONReport struct {
	Version string          `json:"version"`
	Summary LLMJSONSummary  `json:"summary"`
	Results []*models.LLMServer `json:"results"`
}

// LLMJSONSummary aggregates LLM scan results.
type LLMJSONSummary struct {
	Total         int `json:"total"`
	Open          int `json:"open"`
	AuthRequired  int `json:"auth_required"`
	PartiallyOpen int `json:"partially_open"`
	TotalModels   int `json:"total_models"`
}

// WriteLLMJSON writes the LLM scan results as JSON.
func WriteLLMJSON(results []*models.LLMServer, path string) error {
	report := LLMJSONReport{
		Version: "1.0",
		Summary: summarizeLLMResults(results),
		Results: results,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	if path == "" || path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// ── Summary helpers ─────────────────────────────────────────────────────────

func summarizeLLMResults(results []*models.LLMServer) LLMJSONSummary {
	var s LLMJSONSummary
	s.Total = len(results)
	for _, r := range results {
		switch r.AuthStatus {
		case "open":
			s.Open++
		case "auth_required":
			s.AuthRequired++
		case "partially_open":
			s.PartiallyOpen++
		}
		s.TotalModels += r.ModelCount
	}
	return s
}
