package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/agentscan/agentscan/internal/version"
	"github.com/agentscan/agentscan/pkg/config"
	"github.com/agentscan/agentscan/pkg/models"
	"github.com/agentscan/agentscan/pkg/output"
	"github.com/agentscan/agentscan/pkg/scanner"
	"github.com/urfave/cli/v2"
)

func main() {
	app := newApp()

	if err := app.Run(normalizeArgs(os.Args, app.Commands)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newApp() *cli.App {
	return &cli.App{
		Name:    "agentscan",
		Usage:   "AI agent protocol exposure scanner",
		Version: version.Version,
		Commands: []*cli.Command{
			mcpCommand(),
			scanCommand(),
		},
	}
}

// commonFlags returns the flags shared across all protocol subcommands.
func commonFlags() []cli.Flag {
	return []cli.Flag{
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
			Name: "ports",
			Value: strings.Join(func() []string {
				s := make([]string, len(config.DefaultPorts))
				for i, p := range config.DefaultPorts {
					s[i] = fmt.Sprintf("%d", p)
				}
				return s
			}(), ","),
			Usage: "Comma-separated port list",
		},
		&cli.IntFlag{
			Name:    "threads",
			Aliases: []string{"T"},
			Value:   config.DefaultConcurrency,
			Usage:   "Max concurrent TCP connections",
		},
		&cli.IntFlag{
			Name:  "timeout",
			Value: config.DefaultTimeoutConnectMs,
			Usage: "TCP connect timeout (ms)",
		},
		&cli.BoolFlag{
			Name:  "skip-port-scan",
			Usage: "Skip TCP port scan; treat all inputs as open IP:Port (use when feeding masscan/nmap results)",
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
			Name:    "verbose",
			Aliases: []string{"v"},
			Usage:   "Verbose logging: show each open port, current probe target, and response time",
		},
		&cli.BoolFlag{
			Name:    "no-color",
			Aliases: []string{"Cn"},
			Usage:   "Disable colored output",
		},
	}
}

func mcpCommand() *cli.Command {
	return mcpCommandWithAction(runAction)
}

func mcpCommandWithAction(action cli.ActionFunc) *cli.Command {
	flags := append(commonFlags(),
		&cli.BoolFlag{
			Name:  "exclude-honeypots",
			Usage: "Exclude suspected honeypots from results",
		},
		&cli.BoolFlag{
			Name:  "verbose-raw",
			Usage: "Include raw initialize response in JSON output",
		},
		&cli.IntFlag{
			Name:  "mcp-threads",
			Value: 50,
			Usage: "Max concurrent MCP probe connections (default 50; raise for large batches)",
		},
	)
	return &cli.Command{
		Name:                   "mcp",
		Usage:                  "Scan targets for exposed MCP (Model Context Protocol) servers",
		ArgsUsage:              "[TARGET...]",
		UseShortOptionHandling: true,
		Flags:                  flags,
		Action:                 action,
	}
}

func scanCommand() *cli.Command {
	return scanCommandWithAction(runAction)
}

func scanCommandWithAction(action cli.ActionFunc) *cli.Command {
	flags := append(commonFlags(),
		&cli.BoolFlag{
			Name:  "exclude-honeypots",
			Usage: "Exclude suspected honeypots from results",
		},
		&cli.BoolFlag{
			Name:  "verbose-raw",
			Usage: "Include raw initialize response in JSON output",
		},
		&cli.IntFlag{
			Name:  "mcp-threads",
			Value: 50,
			Usage: "Max concurrent MCP probe connections (default 50; raise for large batches)",
		},
	)
	return &cli.Command{
		Name:                   "scan",
		Usage:                  "Scan targets for all supported protocols (currently: MCP)",
		ArgsUsage:              "[TARGET...]",
		UseShortOptionHandling: true,
		Flags:                  flags,
		Action:                 action,
	}
}

func runAction(c *cli.Context) error {
	rawTargets := append(c.StringSlice("target"), c.Args().Slice()...)

	cfg := models.DefaultConfig()
	cfg.Concurrency = c.Int("threads")
	cfg.TimeoutConnectMs = c.Int("timeout")
	cfg.TimeoutHTTPMs = cfg.TimeoutConnectMs * 10
	cfg.TimeoutMCPMs = cfg.TimeoutConnectMs * 20
	cfg.ExcludeHoneypots = c.Bool("exclude-honeypots")
	cfg.Ports = parsePorts(c.String("ports"))
	cfg.VerboseRaw = c.Bool("verbose-raw")
	cfg.Verbose = c.Bool("verbose")
	cfg.MCPConcurrency = c.Int("mcp-threads")
	cfg.SkipPortScan = c.Bool("skip-port-scan")

	noColor := c.Bool("no-color") || output.NoColorEnabled()
	format := c.String("format")
	outputPath := c.String("output")

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

type argFlagSpec struct {
	takesValue bool
}

func normalizeArgs(args []string, commands []*cli.Command) []string {
	if len(args) < 2 {
		return append([]string(nil), args...)
	}

	cmdIndex, cmd := findCommand(args[1:], commands)
	if cmd == nil {
		return append([]string(nil), args...)
	}
	cmdIndex++

	normalized := append([]string(nil), args[:cmdIndex+1]...)
	normalized = append(normalized, normalizeCommandArgs(args[cmdIndex+1:], commandFlagSpecs(cmd))...)
	return normalized
}

func findCommand(args []string, commands []*cli.Command) (int, *cli.Command) {
	for i, arg := range args {
		for _, cmd := range commands {
			if cmd.HasName(arg) {
				return i, cmd
			}
		}
	}
	return -1, nil
}

func commandFlagSpecs(cmd *cli.Command) map[string]argFlagSpec {
	specs := map[string]argFlagSpec{
		"--help":                     {},
		"-help":                      {},
		"-h":                         {},
		"--generate-bash-completion": {},
		"-generate-bash-completion":  {},
	}

	for _, flag := range cmd.Flags {
		spec := argFlagSpec{}
		if docFlag, ok := flag.(cli.DocGenerationFlag); ok {
			spec.takesValue = docFlag.TakesValue()
		}
		for _, name := range flag.Names() {
			specs["--"+name] = spec
			specs["-"+name] = spec
		}
	}

	return specs
}

func normalizeCommandArgs(args []string, flagSpecs map[string]argFlagSpec) []string {
	preTerminator := args
	var terminatorAndAfter []string
	for i, arg := range args {
		if arg == "--" {
			preTerminator = args[:i]
			terminatorAndAfter = args[i:]
			break
		}
	}

	var flagArgs []string
	var positionalArgs []string
	for i := 0; i < len(preTerminator); i++ {
		arg := preTerminator[i]
		flagName := flagTokenName(arg)
		spec, knownFlag := flagSpecs[flagName]

		if flagName != "" && knownFlag {
			flagArgs = append(flagArgs, arg)
			if spec.takesValue && !strings.Contains(arg, "=") && i+1 < len(preTerminator) {
				i++
				flagArgs = append(flagArgs, preTerminator[i])
			}
			continue
		}

		if flagName != "" {
			flagArgs = append(flagArgs, arg)
			continue
		}

		positionalArgs = append(positionalArgs, arg)
	}

	normalized := append(flagArgs, positionalArgs...)
	normalized = append(normalized, terminatorAndAfter...)
	return normalized
}

func flagTokenName(arg string) string {
	if arg == "-" || !strings.HasPrefix(arg, "-") {
		return ""
	}
	if idx := strings.Index(arg, "="); idx >= 0 {
		return arg[:idx]
	}
	return arg
}
