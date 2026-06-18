package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

type parsedCLI struct {
	Targets          []string
	File             string
	Ports            string
	Threads          int
	Timeout          int
	Output           string
	Format           string
	Verbose          bool
	NoColor          bool
	SkipPortScan     bool
	ExcludeHoneypots bool
	VerboseRaw       bool
	MCPThreads       int
}

func TestNormalizeArgsParsesFlagsAfterTargets(t *testing.T) {
	args := []string{
		"agentscan", "mcp", "positional.example",
		"--format", "json",
		"--output", "out.json",
		"--timeout", "123",
		"--threads", "7",
		"--ports", "80,443",
		"--file", "targets.txt",
		"--skip-port-scan",
		"--mcp-threads", "5",
		"--exclude-honeypots",
		"--verbose-raw",
		"--verbose",
		"--no-color",
		"--target", "flagged.example",
	}

	got := parseCLIForTest(t, args)
	want := parsedCLI{
		Targets:          []string{"flagged.example", "positional.example"},
		File:             "targets.txt",
		Ports:            "80,443",
		Threads:          7,
		Timeout:          123,
		Output:           "out.json",
		Format:           "json",
		Verbose:          true,
		NoColor:          true,
		SkipPortScan:     true,
		ExcludeHoneypots: true,
		VerboseRaw:       true,
		MCPThreads:       5,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed CLI mismatch\nwant: %#v\n got: %#v", want, got)
	}
}

func TestNormalizeArgsParsesAliasesAfterTargets(t *testing.T) {
	before := []string{
		"agentscan", "mcp",
		"-t", "flagged.example",
		"-f", "targets.txt",
		"-T", "9",
		"-o", "alias.json",
		"-Cn",
		"positional.example",
	}
	after := []string{
		"agentscan", "mcp", "positional.example",
		"-t", "flagged.example",
		"-f", "targets.txt",
		"-T", "9",
		"-o", "alias.json",
		"-Cn",
	}

	want := parseCLIForTest(t, before)
	got := parseCLIForTest(t, after)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("alias flags should parse the same before and after targets\nwant: %#v\n got: %#v", want, got)
	}
	if contains(got.Targets, "-Cn") {
		t.Fatalf("-Cn was parsed as a target: %#v", got.Targets)
	}
}

func TestNormalizeArgsSupportsScanCommand(t *testing.T) {
	got := parseCLIForTest(t, []string{
		"agentscan", "scan", "positional.example",
		"--format", "json",
		"--mcp-threads", "11",
	})

	if got.Format != "json" {
		t.Fatalf("format = %q, want json", got.Format)
	}
	if got.MCPThreads != 11 {
		t.Fatalf("mcp-threads = %d, want 11", got.MCPThreads)
	}
	if !reflect.DeepEqual(got.Targets, []string{"positional.example"}) {
		t.Fatalf("targets = %#v, want positional.example", got.Targets)
	}
}

func TestMCPHelpShowsGroupedUsefulOptions(t *testing.T) {
	var buf bytes.Buffer
	app := newApp()
	app.Writer = &buf

	if err := app.Run([]string{"agentscan", "mcp", "-h"}); err != nil {
		t.Fatalf("app.Run() error = %v", err)
	}
	help := buf.String()

	for _, want := range []string{
		"Input",
		"Scan",
		"Output",
		"Filter / Debug",
		"-t, --target TARGET",
		"-f, --file FILE",
		"--ports LIST",
		"-T, --threads N",
		"--timeout MS",
		"--skip-port-scan",
		"--mcp-threads N",
		"-o, --output FILE",
		"HTML reports",
		"--format terminal|json",
		"-v, --verbose",
		"--no-color, --Cn",
		"--exclude-honeypots",
		"--verbose-raw",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help missing %q\n%s", want, help)
		}
	}

	for _, noisy := range []string{
		`8000,8001,443`,
		"(default: false)",
		"[ --target value, -t value ]",
	} {
		if strings.Contains(help, noisy) {
			t.Fatalf("help should not contain noisy text %q\n%s", noisy, help)
		}
	}
}

func parseCLIForTest(t *testing.T, args []string) parsedCLI {
	t.Helper()

	var parsed parsedCLI
	capture := func(c *cli.Context) error {
		parsed = parsedCLI{
			Targets:          append(c.StringSlice("target"), c.Args().Slice()...),
			File:             c.String("file"),
			Ports:            c.String("ports"),
			Threads:          c.Int("threads"),
			Timeout:          c.Int("timeout"),
			Output:           c.String("output"),
			Format:           c.String("format"),
			Verbose:          c.Bool("verbose"),
			NoColor:          c.Bool("no-color"),
			SkipPortScan:     c.Bool("skip-port-scan"),
			ExcludeHoneypots: c.Bool("exclude-honeypots"),
			VerboseRaw:       c.Bool("verbose-raw"),
			MCPThreads:       c.Int("mcp-threads"),
		}
		return nil
	}
	app := &cli.App{
		Name: "agentscan",
		Commands: []*cli.Command{
			mcpCommandWithAction(capture),
			scanCommandWithAction(capture),
		},
	}

	if err := app.Run(normalizeArgs(args, app.Commands)); err != nil {
		t.Fatalf("app.Run() error = %v", err)
	}
	return parsed
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
