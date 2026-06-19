package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/agentscan/agentscan/internal/version"
	"github.com/agentscan/agentscan/pkg/config"
	"github.com/agentscan/agentscan/pkg/models"
	"github.com/agentscan/agentscan/pkg/output"
	"github.com/agentscan/agentscan/pkg/scanner"
	"github.com/urfave/cli/v2"
)

// loadDict loads the DictSet from --dict-dir (if set) and prints any warnings.
func loadDict(dictDir string) *config.DictSet {
	ds, err := config.LoadDictSet(dictDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] dict-dir: %v\n", err)
	}
	return ds
}

func main() {
	app := newApp()

	if err := app.Run(normalizeArgs(os.Args, app.Commands)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newApp() *cli.App {
	return &cli.App{
		Name:      "agentscan",
		Usage:     "Scan exposed AI agent services",
		UsageText: "agentscan <command> [options] [target...]",
		Version:   version.Version,
		Commands: []*cli.Command{
			mcpCommand(),
			a2aCommand(),
			scanCommand(),
		},
	}
}

// commonFlags returns the flags shared across all protocol subcommands.
func commonFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{
			Name:     "target",
			Aliases:  []string{"t"},
			Usage:    "Target to scan",
			Category: "Input",
		},
		&cli.StringFlag{
			Name:     "file",
			Aliases:  []string{"f"},
			Usage:    "Read targets from file",
			Category: "Input",
		},
		&cli.StringFlag{
			Name:        "dict-dir",
			Usage:       "Directory containing custom dictionary txt files (mcp_ports.txt, a2a_ports.txt, mcp_paths.txt, ...)",
			DefaultText: "",
			Category:    "Scan",
		},
		&cli.StringFlag{
			Name:        "ports",
			Usage:       "Ports to scan, comma-separated (overrides dict-dir / built-in list)",
			DefaultText: "built-in list for each protocol",
			Category:    "Scan",
		},
		&cli.IntFlag{
			Name:     "threads",
			Aliases:  []string{"T"},
			Value:    config.DefaultConcurrency,
			Usage:    "TCP scan concurrency",
			Category: "Scan",
		},
		&cli.IntFlag{
			Name:        "timeout",
			Value:       config.DefaultTimeoutConnectMs,
			Usage:       "TCP timeout in ms",
			DefaultText: "2000",
			Category:    "Scan",
		},
		&cli.BoolFlag{
			Name:               "skip-port-scan",
			Usage:              "Treat input as known open host:port entries",
			DisableDefaultText: true,
			Category:           "Scan",
		},
		&cli.StringFlag{
			Name:     "output",
			Aliases:  []string{"o"},
			Usage:    "Write JSON results to file",
			Category: "Output",
		},
		&cli.StringFlag{
			Name:        "format",
			Value:       "terminal",
			Usage:       "Output format: terminal or json",
			DefaultText: "terminal",
			Category:    "Output",
		},
		&cli.BoolFlag{
			Name:               "verbose",
			Aliases:            []string{"v"},
			Usage:              "Show probe progress details",
			DisableDefaultText: true,
			Category:           "Output",
		},
		&cli.BoolFlag{
			Name:               "no-color",
			Aliases:            []string{"Cn"},
			Usage:              "Disable ANSI colors",
			DisableDefaultText: true,
			Category:           "Output",
		},
	}
}

const scanHelpTemplate = `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.UsageText}}

EXAMPLES:
   agentscan {{.Name}} 192.168.1.0/24
   agentscan {{.Name}} -f targets.txt --skip-port-scan -o results.json

OPTIONS:
   Input
     TARGET...                 IP, CIDR, range, domain, host:port, or URL
     -t, --target TARGET       Add target (repeatable)
     -f, --file FILE           Read targets from file

   Scan
     --ports LIST              Ports to scan (overrides dict-dir / built-in list)
     --dict-dir DIR            Directory with custom dict txt files
     --skip-port-scan          Input is already open host:port
     -T, --threads N           TCP scan concurrency (default: 500)
     --timeout MS              TCP timeout (default: 2000)
     --mcp-threads N           MCP probe concurrency (default: 50)

   Output
     HTML reports             Auto-written to agentscan-report-*/ and agentscan-a2a-*/
     -o, --output FILE         Write MCP JSON; A2A JSON written to FILE_a2a.json
     --format terminal|json    Output format (default: terminal)
     -v, --verbose             Show probe details
     --no-color, --Cn          Disable colors

   Filter / Debug
     --exclude-honeypots       Hide suspected honeypots
     --verbose-raw             Include raw initialize response in JSON
     -h, --help                Show help
`

func mcpCommand() *cli.Command {
	return mcpCommandWithAction(runAction)
}

func mcpCommandWithAction(action cli.ActionFunc) *cli.Command {
	flags := append(commonFlags(),
		&cli.BoolFlag{
			Name:               "exclude-honeypots",
			Usage:              "Hide suspected honeypots",
			DisableDefaultText: true,
			Category:           "Filter",
		},
		&cli.BoolFlag{
			Name:               "verbose-raw",
			Usage:              "Include raw MCP initialize response in JSON",
			DisableDefaultText: true,
			Category:           "Debug",
		},
		&cli.IntFlag{
			Name:        "mcp-threads",
			Value:       50,
			Usage:       "MCP probe concurrency",
			DefaultText: "50",
			Category:    "Scan",
		},
	)
	return &cli.Command{
		Name:                   "mcp",
		Usage:                  "Scan MCP servers",
		UsageText:              "agentscan mcp [options] [target...]",
		UseShortOptionHandling: true,
		Flags:                  flags,
		Action:                 action,
		CustomHelpTemplate:     scanHelpTemplate,
	}
}

const a2aHelpTemplate = `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.UsageText}}

EXAMPLES:
   agentscan {{.Name}} example.com
   agentscan {{.Name}} -f targets.txt --skip-port-scan -o results.json

OPTIONS:
   Input
     TARGET...                 IP, CIDR, range, domain, host:port, or URL
     -t, --target TARGET       Add target (repeatable)
     -f, --file FILE           Read targets from file

   Scan
     --ports LIST              Ports to scan (overrides dict-dir / built-in list)
     --dict-dir DIR            Directory with custom dict txt files
     --skip-port-scan          Input is already open host:port
     -T, --threads N           TCP scan concurrency (default: 500)
     --timeout MS              TCP timeout (default: 2000)
     --a2a-threads N           A2A probe concurrency (default: 50)

   Output
     -o, --output FILE         Write JSON report
     --format terminal|json    Output format (default: terminal)
     -v, --verbose             Show probe details
     --no-color, --Cn          Disable colors

   Filter / Debug
     --include-probable        Include probable agent-discovery matches
     --verbose-raw             Include raw A2A card response in JSON
     -h, --help                Show help
`

func a2aCommand() *cli.Command {
	return a2aCommandWithAction(runA2AAction)
}

func a2aCommandWithAction(action cli.ActionFunc) *cli.Command {
	flags := append(commonFlags(),
		&cli.BoolFlag{
			Name:               "include-probable",
			Usage:              "Include probable agent-discovery matches",
			DisableDefaultText: true,
			Category:           "Filter",
		},
		&cli.BoolFlag{
			Name:               "verbose-raw",
			Usage:              "Include raw A2A card response in JSON",
			DisableDefaultText: true,
			Category:           "Debug",
		},
		&cli.IntFlag{
			Name:        "a2a-threads",
			Value:       50,
			Usage:       "A2A probe concurrency",
			DefaultText: "50",
			Category:    "Scan",
		},
	)
	return &cli.Command{
		Name:                   "a2a",
		Usage:                  "Scan A2A Agent Cards",
		UsageText:              "agentscan a2a [options] [target...]",
		UseShortOptionHandling: true,
		Flags:                  flags,
		Action:                 action,
		CustomHelpTemplate:     a2aHelpTemplate,
	}
}

func scanCommand() *cli.Command {
	return scanCommandWithAction(runAction)
}

func scanCommandWithAction(action cli.ActionFunc) *cli.Command {
	flags := append(commonFlags(),
		&cli.BoolFlag{
			Name:               "exclude-honeypots",
			Usage:              "Hide suspected honeypots",
			DisableDefaultText: true,
			Category:           "Filter",
		},
		&cli.BoolFlag{
			Name:               "verbose-raw",
			Usage:              "Include raw MCP initialize response in JSON",
			DisableDefaultText: true,
			Category:           "Debug",
		},
		&cli.IntFlag{
			Name:        "mcp-threads",
			Value:       50,
			Usage:       "MCP probe concurrency",
			DefaultText: "50",
			Category:    "Scan",
		},
	)
	return &cli.Command{
		Name:                   "scan",
		Usage:                  "Scan all supported protocols",
		UsageText:              "agentscan scan [options] [target...]",
		UseShortOptionHandling: true,
		Flags:                  flags,
		Action:                 action,
		CustomHelpTemplate:     scanHelpTemplate,
	}
}

func runAction(c *cli.Context) error {
	rawTargets := append(c.StringSlice("target"), c.Args().Slice()...)

	ds := loadDict(c.String("dict-dir"))

	cfg := models.DefaultConfig()
	cfg.Dict = ds
	cfg.Ports = ds.MCPPorts // default: dict (custom or built-in MCP ports)
	if c.IsSet("ports") {
		cfg.Ports = parsePorts(c.String("ports"))
	}
	cfg.Concurrency = c.Int("threads")
	cfg.TimeoutConnectMs = c.Int("timeout")
	cfg.TimeoutHTTPMs = cfg.TimeoutConnectMs * 10
	cfg.TimeoutMCPMs = cfg.TimeoutConnectMs * 20
	cfg.ExcludeHoneypots = c.Bool("exclude-honeypots")
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

func runA2AAction(c *cli.Context) error {
	rawTargets := append(c.StringSlice("target"), c.Args().Slice()...)

	ds := loadDict(c.String("dict-dir"))

	cfg := models.DefaultA2AConfig()
	cfg.Dict = ds
	cfg.Ports = ds.A2APorts // default: dict (custom or built-in A2A ports)
	if c.IsSet("ports") {
		cfg.Ports = parsePorts(c.String("ports"))
	}
	cfg.Concurrency = c.Int("threads")
	cfg.TimeoutConnectMs = c.Int("timeout")
	cfg.TimeoutHTTPMs = cfg.TimeoutConnectMs * 10
	// A2A probe = card fetch + 1-2 JSON-RPC calls; 4x is sufficient and avoids 45s per-candidate caps
	cfg.TimeoutMCPMs = cfg.TimeoutConnectMs * 4
	cfg.VerboseRaw = c.Bool("verbose-raw")
	cfg.Verbose = c.Bool("verbose")
	cfg.MCPConcurrency = c.Int("a2a-threads")
	cfg.SkipPortScan = c.Bool("skip-port-scan")

	noColor := c.Bool("no-color") || output.NoColorEnabled()
	format := c.String("format")
	outputPath := c.String("output")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	_, err := scanner.RunA2AScan(
		ctx,
		rawTargets,
		c.String("file"),
		cfg,
		outputPath,
		format,
		noColor,
		c.Bool("include-probable"),
	)
	return err
}

func parsePorts(s string) []int {
	parts := strings.Split(s, ",")
	var ports []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		n, err := strconv.Atoi(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] invalid port %q: %v\n", p, err)
			continue
		}
		if n < 1 || n > 65535 {
			fmt.Fprintf(os.Stderr, "[WARN] port %d out of range (1-65535), skipped\n", n)
			continue
		}
		ports = append(ports, n)
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
