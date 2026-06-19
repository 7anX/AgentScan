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
	bold, reset, riskColor := "", "", ""
	if !noColor && !NoColorEnabled() {
		bold = "\033[1m"
		reset = "\033[0m"
		switch s.RiskLevel {
		case "CRITICAL":
			riskColor = "\033[31m\033[1m" // red bold
		case "HIGH":
			riskColor = "\033[31m" // red
		case "MEDIUM":
			riskColor = "\033[33m\033[1m" // yellow bold
		}
	}

	target := fmt.Sprintf("%s:%d", s.IP, s.Port)
	if s.Hostname != "" && s.Hostname != s.IP {
		target = fmt.Sprintf("%s:%d", s.Hostname, s.Port)
	}

	fmt.Fprintf(w, "%s[LLM]%s %-25s %-15s %-14s %s%-8s%s  models=%d  score=%.2f\n",
		bold, reset,
		target,
		s.Framework,
		s.AuthStatus,
		riskColor, s.RiskLevel, reset,
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
	fmt.Fprintln(w)
}

// PrintLLMSummary prints the final LLM scan summary.
func PrintLLMSummary(results []*models.LLMServer, noColor bool) {
	FprintLLMSummary(os.Stdout, results, noColor)
}

// FprintLLMSummary writes the LLM scan summary to a writer.
func FprintLLMSummary(w io.Writer, results []*models.LLMServer, noColor bool) {
	bold, reset := "", ""
	if !noColor && !NoColorEnabled() {
		bold = "\033[1m"
		reset = "\033[0m"
	}

	summary := summarizeLLMResults(results)

	fmt.Fprintf(w, "\n%s── LLM Summary ──%s\n", bold, reset)
	fmt.Fprintf(w, "  Total:     %d\n", summary.Total)
	fmt.Fprintf(w, "  Open:      %d\n", summary.Open)
	fmt.Fprintf(w, "  Auth-req:  %d\n", summary.AuthRequired)
	fmt.Fprintf(w, "  Critical:  %d\n", summary.Critical)
	fmt.Fprintf(w, "  High:      %d\n", summary.High)
	fmt.Fprintf(w, "  Medium:    %d\n", summary.Medium)
	fmt.Fprintf(w, "  Models:    %d\n", summary.TotalModels)
	fmt.Fprintln(w)
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
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
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
		switch r.RiskLevel {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		}
		s.TotalModels += r.ModelCount
	}
	return s
}
