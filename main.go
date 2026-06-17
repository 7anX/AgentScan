package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/agentscan/agentscan/internal/version"
	"github.com/agentscan/agentscan/pkg/models"
	"github.com/agentscan/agentscan/pkg/output"
	"github.com/agentscan/agentscan/pkg/scanner"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:    "agentscan",
		Usage:   "MCP exposure surface scanner",
		Version: version.Version,
		Commands: []*cli.Command{
			scanCommand(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func scanCommand() *cli.Command {
	return &cli.Command{
		Name:                   "scan",
		Usage:                  "Scan targets for exposed MCP servers",
		ArgsUsage:              "[TARGET...]",
		UseShortOptionHandling: true,
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "target",
				Aliases: []string{"t"},
				Usage:   "Target(s): IP, CIDR, IP range (1.1.1.1-2.2.2.2), domain, host:port, URL. Repeatable.",
			},
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Usage:   "File with targets (one per line, # comments supported)",
			},
			&cli.StringFlag{
				Name:  "ports",
				Value: "80,443,8000,8080,8443,3000,3001,4000,5000,9000",
				Usage: "Comma-separated port list",
			},
			&cli.IntFlag{
				Name:    "threads",
				Aliases: []string{"T"},
				Value:   500,
				Usage:   "Max concurrent TCP connections",
			},
			&cli.IntFlag{
				Name:  "timeout",
				Value: 500,
				Usage: "TCP connect timeout (ms)",
			},
			&cli.BoolFlag{
				Name:  "exclude-honeypots",
				Usage: "Exclude suspected honeypots from results",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "JSON output file path",
			},
			&cli.StringFlag{
				Name:  "format",
				Value: "terminal",
				Usage: "Output format: terminal|json",
			},
			&cli.BoolFlag{
				Name:  "verbose-raw",
				Usage: "Include raw initialize response in JSON output",
			},
			&cli.BoolFlag{
				Name:  "no-color",
				Aliases: []string{"Cn"},
				Usage: "Disable colored output",
			},
		},
		Action: func(c *cli.Context) error {
			// 合并所有目标来源：-t flag + positional args（过滤掉被误识别的 flag）
			rawTargets := append(c.StringSlice("target"), filterNonFlags(c.Args().Slice())...)

			cfg := models.DefaultConfig()
			cfg.Concurrency = c.Int("threads")
			cfg.TimeoutConnectMs = c.Int("timeout")
			cfg.TimeoutHTTPMs = cfg.TimeoutConnectMs * 10
			cfg.TimeoutMCPMs = cfg.TimeoutConnectMs * 20
			cfg.ExcludeHoneypots = c.Bool("exclude-honeypots")
			cfg.Ports = parsePorts(c.String("ports"))
			cfg.VerboseRaw = c.Bool("verbose-raw")

			noColor := c.Bool("no-color") || hasArgAnywhere("--no-color") || hasArgAnywhere("-Cn") || output.NoColorEnabled()

			// 对于在 positional arg 后面的 valued flag，urfave/cli 无法解析，
			// 优先从 os.Args 直接读取，覆盖 urfave/cli 的默认值
			format := getArgValue("--format")
			if format == "" {
				format = c.String("format") // urfave/cli 解析到的（可能是默认值 "terminal"）
			}
			outputPath := getArgValue("--output")
			if outputPath == "" {
				outputPath = getArgValue("-o")
			}
			if outputPath == "" {
				outputPath = c.String("output")
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			_, err := scanner.RunScan(
				ctx,
				rawTargets,
				c.String("file"),
				cfg,
				outputPath,
				format,
				noColor,
			)
			return err
		},
	}
}

func parsePorts(s string) []int {
	parts := strings.Split(s, ",")
	var ports []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		var port int
		fmt.Sscanf(p, "%d", &port)
		if port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		return models.DefaultConfig().Ports
	}
	return ports
}

func hasArgAnywhere(flag string) bool {
	for _, arg := range os.Args {
		if arg == flag {
			return true
		}
	}
	return false
}

// getArgValue 从 os.Args 任意位置读取 --flag value 的值
func getArgValue(flag string) string {
	for i, arg := range os.Args {
		if arg == flag && i+1 < len(os.Args) {
			next := os.Args[i+1]
			if !strings.HasPrefix(next, "-") {
				return next
			}
		}
	}
	return ""
}

func filterNonFlags(args []string) []string {
	var targets []string
	skipNext := false
	valuedFlags := map[string]bool{
		"--file": true, "-f": true,
		"--ports": true, "--threads": true, "-T": true,
		"--timeout": true,
		"--output": true, "-o": true,
		"--format": true,
		"--target": true, "-t": true,
	}
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(arg, "--") || (strings.HasPrefix(arg, "-") && len(arg) == 2) {
			if valuedFlags[arg] {
				skipNext = true
			}
			continue
		}
		targets = append(targets, arg)
	}
	return targets
}