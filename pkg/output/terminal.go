package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/agentscan/agentscan/pkg/models"
)

// NoColorEnabled reports whether color should be disabled.
// Respects the NO_COLOR environment variable (https://no-color.org/).
func NoColorEnabled() bool {
	return os.Getenv("NO_COLOR") != ""
}

// ANSI 颜色
const (
	colorReset  = "\033[0m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
)

// PrintServer 实时打印单个 MCP 服务器发现结果
func PrintServer(s *models.MCPServer, noColor bool) {
	bold, reset := "", ""
	if !noColor {
		bold = colorGreen + colorBold
		reset = colorReset
	}

	auth := "no-auth"
	if !s.NoAuth {
		auth = "auth"
	}

	fmt.Printf("%s[MCP]%s %s:%d  %s  %s  v=%s  %s\n",
		bold, reset,
		s.IP, s.Port,
		s.Endpoint,
		s.Transport,
		s.ProtocolVersion,
		auth,
	)

	if s.ServerName != "" {
		fmt.Printf("      server=%q  tools=%d\n", s.ServerName+"/"+s.ServerVersion, s.ToolCount)
	} else {
		fmt.Printf("      tools=%d\n", s.ToolCount)
	}

	// 蜜罐信号
	if s.Honeypot.Suspected {
		hp := ""
		if !noColor {
			hp = colorYellow
		}
		fmt.Printf("      %s[HONEYPOT] score=%d  signals: %s%s\n",
			hp, s.Honeypot.Score,
			strings.Join(s.Honeypot.Signals, ", "),
			reset)
	}
	fmt.Println()
}

// PrintHoneypot 专门打印蜜罐结果（保留兼容，内部调 PrintServer）
func PrintHoneypot(s *models.MCPServer, noColor bool) {
	PrintServer(s, noColor)
}

// PrintSummary 扫描完成后打印汇总
func PrintSummary(results []*models.MCPServer, noColor bool) {
	bold, reset := "", ""
	if !noColor {
		bold = colorBold
		reset = colorReset
	}

	total := len(results)
	honeypots := 0
	noAuthCount := 0
	for _, r := range results {
		if r.Honeypot.Suspected {
			honeypots++
		}
		if r.NoAuth {
			noAuthCount++
		}
	}

	fmt.Printf("\n%s=== AgentScan Summary ===%s\n", bold, reset)
	fmt.Printf("MCP servers found : %d\n", total)
	fmt.Printf("  Unauthenticated : %d\n", noAuthCount)
	fmt.Printf("  Honeypots       : %d\n", honeypots)
}
