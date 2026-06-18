package output

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/agentscan/agentscan/pkg/models"
)

// NoColorEnabled reports whether color should be disabled.
// Respects the NO_COLOR environment variable (https://no-color.org/).
func NoColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	if os.Getenv("AGENTSCAN_COLOR") == "always" || os.Getenv("CLICOLOR_FORCE") != "" || os.Getenv("FORCE_COLOR") != "" {
		return false
	}
	return runtime.GOOS == "windows"
}

const (
	colorReset  = "\033[0m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
)

// PrintServer prints one MCP server finding as a compact terminal block.
func PrintServer(s *models.MCPServer, noColor bool) {
	FprintServer(os.Stdout, s, noColor)
}

func FprintServer(w io.Writer, s *models.MCPServer, noColor bool) {
	bold, reset, statusColor, warning := "", "", "", ""
	if !noColor {
		bold = colorBold
		reset = colorReset
		warning = colorYellow
	}

	auth := "no-auth"
	if s.AuthRequired {
		auth = "auth-required"
		if !noColor {
			statusColor = colorYellow + colorBold
		}
	} else if !s.NoAuth {
		auth = "auth"
	} else if !noColor {
		statusColor = colorGreen + colorBold
	}

	target := fmt.Sprintf("%s:%d%s", s.IP, s.Port, s.Endpoint)
	version := s.ProtocolVersion
	if version == "" {
		version = "unknown"
	}

	fmt.Fprintf(w, "%s[MCP]%s %-30s %-15s %-12s %s%s%s\n",
		bold, reset,
		target,
		transportLabel(s.Transport),
		version,
		statusColor, auth, reset,
	)

	if s.AuthRequired {
		fmt.Fprintf(w, "      %sauth%s     tools/resources unavailable until authenticated\n", warning, reset)
	} else {
		if server := serverLabel(s); server != "" {
			fmt.Fprintf(w, "      server   %s\n", server)
		}
		fmt.Fprintf(w, "      exposed  tools=%d  resources=%d  templates=%d  prompts=%d\n",
			s.ToolCount, s.ResourceCount, s.ResourceTemplateCount, s.PromptCount)
	}

	if s.Honeypot.Suspected {
		honeypotColor := ""
		if !noColor {
			honeypotColor = colorYellow
		}
		fmt.Fprintf(w, "      %shoneypot%s score=%d  signals=%s\n",
			honeypotColor, reset,
			s.Honeypot.Score,
			strings.Join(s.Honeypot.Signals, ", "))
	}

	fmt.Fprintln(w)
}

func transportLabel(t models.Transport) string {
	switch t {
	case models.TransportStreamableHTTP:
		return "streamable-http"
	case models.TransportHTTPSSELegacy:
		return "sse-legacy"
	default:
		if t == "" {
			return "unknown"
		}
		return string(t)
	}
}

func serverLabel(s *models.MCPServer) string {
	switch {
	case s.ServerName != "" && s.ServerVersion != "" && s.ServerName != s.ServerVersion:
		return fmt.Sprintf("%s (%s)", s.ServerName, s.ServerVersion)
	case s.ServerName != "":
		return s.ServerName
	case s.ServerVersion != "":
		return s.ServerVersion
	default:
		return ""
	}
}

// PrintHoneypot prints a honeypot finding.
func PrintHoneypot(s *models.MCPServer, noColor bool) {
	PrintServer(s, noColor)
}

// PrintSummary prints the final scan summary.
func PrintSummary(results []*models.MCPServer, noColor bool) {
	bold, reset := "", ""
	if !noColor {
		bold = colorBold
		reset = colorReset
	}

	total := len(results)
	honeypots := 0
	noAuthCount := 0
	authRequired := 0
	totalTools := 0
	totalResources := 0
	totalResTemplates := 0
	totalPrompts := 0
	for _, r := range results {
		if r.Honeypot.Suspected {
			honeypots++
		}
		if r.NoAuth {
			noAuthCount++
		}
		if r.AuthRequired {
			authRequired++
		}
		totalTools += r.ToolCount
		totalResources += r.ResourceCount
		totalResTemplates += r.ResourceTemplateCount
		totalPrompts += r.PromptCount
	}

	fmt.Printf("\n%sAgentScan summary%s\n", bold, reset)
	fmt.Printf("%-10s %8s %8s %13s %10s\n", "Protocol", "Servers", "No-auth", "Auth-required", "Honeypots")
	fmt.Printf("%-10s %8d %8d %13d %10d\n", "MCP", total, noAuthCount, authRequired, honeypots)
	fmt.Printf("%-10s %8d %8d %13d %10d\n", "Total", total, noAuthCount, authRequired, honeypots)
	fmt.Printf("Exposure   tools=%d  resources=%d  templates=%d  prompts=%d\n",
		totalTools, totalResources, totalResTemplates, totalPrompts)
}
