package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/agentscan/agentscan/pkg/config"
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
	Proxy            string
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
		"--proxy", "socks5://127.0.0.1:1080",
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
		Proxy:            "socks5://127.0.0.1:1080",
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
		"--proxy", "http://127.0.0.1:8080",
	})

	if got.Format != "json" {
		t.Fatalf("format = %q, want json", got.Format)
	}
	if got.MCPThreads != 11 {
		t.Fatalf("mcp-threads = %d, want 11", got.MCPThreads)
	}
	if got.Proxy != "http://127.0.0.1:8080" {
		t.Fatalf("proxy = %q, want http://127.0.0.1:8080", got.Proxy)
	}
	if !reflect.DeepEqual(got.Targets, []string{"positional.example"}) {
		t.Fatalf("targets = %#v, want positional.example", got.Targets)
	}
}

func TestLoadDictFallsBackWhenCustomDirFails(t *testing.T) {
	ds := loadDict(t.TempDir() + "/missing")
	if ds == nil {
		t.Fatal("loadDict returned nil")
	}
	if len(ds.MCPPorts) == 0 || len(ds.A2APorts) == 0 {
		t.Fatalf("fallback dict should include built-in ports: %#v", ds)
	}
}

func TestAllProtocolPortsIncludesA2AAndLLMDefaults(t *testing.T) {
	got := allProtocolPorts(&config.DictSet{
		MCPPorts: []int{8000, 443},
		A2APorts: []int{443, 4010},
		LLMPorts: []int{11434, 8000},
	})
	want := []int{8000, 443, 4010, 11434}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allProtocolPorts() = %v, want %v", got, want)
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
		"--proxy URL",
		"--mcp-threads N",
		"-o, --output FILE",
		"HTML reports",
		"A2A/LLM JSON",
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

func TestA2ACommandParsesFlagsAfterTargets(t *testing.T) {
	args := []string{
		"agentscan", "a2a", "positional.example",
		"--format", "json",
		"--output", "a2a.json",
		"--skip-port-scan",
		"--proxy", "socks4://127.0.0.1:1080",
		"--a2a-threads", "17",
		"--include-probable",
		"--verbose-raw",
		"--target", "flagged.example",
	}

	got := parseA2ACLIForTest(t, args)
	if !reflect.DeepEqual(got.Targets, []string{"flagged.example", "positional.example"}) {
		t.Fatalf("targets = %#v", got.Targets)
	}
	if got.Format != "json" || got.Output != "a2a.json" {
		t.Fatalf("format/output = %q/%q, want json/a2a.json", got.Format, got.Output)
	}
	if !got.SkipPortScan || !got.IncludeProbable || !got.VerboseRaw {
		t.Fatalf("boolean flags not parsed: %#v", got)
	}
	if got.Proxy != "socks4://127.0.0.1:1080" {
		t.Fatalf("proxy = %q, want socks4://127.0.0.1:1080", got.Proxy)
	}
	if got.A2AThreads != 17 {
		t.Fatalf("a2a threads = %d, want 17", got.A2AThreads)
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
			Proxy:            c.String("proxy"),
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

type parsedA2ACLI struct {
	Targets         []string
	Output          string
	Format          string
	SkipPortScan    bool
	IncludeProbable bool
	VerboseRaw      bool
	A2AThreads      int
	Proxy           string
}

func parseA2ACLIForTest(t *testing.T, args []string) parsedA2ACLI {
	t.Helper()

	var parsed parsedA2ACLI
	capture := func(c *cli.Context) error {
		parsed = parsedA2ACLI{
			Targets:         append(c.StringSlice("target"), c.Args().Slice()...),
			Output:          c.String("output"),
			Format:          c.String("format"),
			SkipPortScan:    c.Bool("skip-port-scan"),
			IncludeProbable: c.Bool("include-probable"),
			VerboseRaw:      c.Bool("verbose-raw"),
			A2AThreads:      c.Int("a2a-threads"),
			Proxy:           c.String("proxy"),
		}
		return nil
	}
	app := &cli.App{
		Name: "agentscan",
		Commands: []*cli.Command{
			a2aCommandWithAction(capture),
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
