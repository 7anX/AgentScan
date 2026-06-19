package scanner

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentscan/agentscan/pkg/llmtpl"
	"github.com/agentscan/agentscan/pkg/models"
	"github.com/agentscan/agentscan/pkg/netproxy"
	"github.com/agentscan/agentscan/pkg/output"
	"github.com/agentscan/agentscan/pkg/target"
)

// LLMPipeline scans for exposed LLM inference APIs.
type LLMPipeline struct {
	cfg         models.ScanConfig
	noColor     bool
	probeLabel  string
	onFound     func(*models.LLMServer)
	engine      *llmtpl.Engine
	templateDir string
}

// NewLLMPipeline creates a new LLM scanning pipeline.
// templateDir can be empty to use embedded templates only.
func NewLLMPipeline(cfg models.ScanConfig, noColor bool, onFound func(*models.LLMServer), templateDir string) (*LLMPipeline, error) {
	templates, err := llmtpl.LoadTemplates(templateDir)
	if err != nil {
		return nil, fmt.Errorf("load LLM templates: %w", err)
	}
	engine, err := llmtpl.NewEngine(templates)
	if err != nil {
		return nil, fmt.Errorf("create LLM engine: %w", err)
	}
	return &LLMPipeline{
		cfg:         cfg,
		noColor:     noColor,
		probeLabel:  "--- LLM probe    ",
		onFound:     onFound,
		engine:      engine,
		templateDir: templateDir,
	}, nil
}

// Run executes the full pipeline: port scan → HTTP filter → LLM probe.
func (p *LLMPipeline) Run(ctx context.Context, targets []target.Target) []*models.LLMServer {
	var portResults []PortResult
	if p.cfg.SkipPortScan {
		fmt.Fprintf(os.Stderr, "[1/3] port scan    SKIPPED (--skip-port-scan)\n\n")
		portResults = make([]PortResult, 0, len(targets))
		for _, t := range targets {
			portResults = append(portResults, PortResult{
				IP: t.IP, Port: t.Port, Hostname: t.Hostname,
				URLPath: t.URLPath, Proto: t.Proto, Open: true,
			})
		}
	} else {
		portResults = ScanPorts(ctx, targets, p.cfg.Concurrency, p.cfg.TimeoutConnectMs, p.cfg.Verbose, p.cfg.DelayMs)
	}
	if len(portResults) == 0 {
		fmt.Fprintf(os.Stderr, "      no open ports found\n\n")
		return nil
	}

	httpTimeout := p.cfg.TimeoutHTTPMs
	if p.cfg.SkipPortScan && httpTimeout > p.cfg.TimeoutConnectMs*3 {
		httpTimeout = p.cfg.TimeoutConnectMs * 3
	}
	fmt.Fprintf(os.Stderr, "[2/3] http filter  %d ports\n", len(portResults))
	candidates := FilterHTTP(ctx, portResults, httpTimeout, p.cfg.Concurrency, p.cfg.Dict)
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "      no HTTP services found\n\n")
		return nil
	}
	fmt.Fprintf(os.Stderr, "      %d candidates\n\n", len(candidates))

	return p.RunFromCandidates(ctx, candidates)
}

// RunFromCandidates runs LLM probes against already-filtered HTTP candidates.
// Used by agentscan scan to reuse the shared port scan and HTTP filter results.
func (p *LLMPipeline) RunFromCandidates(ctx context.Context, candidates []HTTPCandidate) []*models.LLMServer {
	if len(candidates) == 0 {
		return nil
	}
	total := int64(len(candidates))
	var done atomic.Int64
	var displayMu sync.Mutex
	stopProgress := make(chan struct{})
	var progressWG sync.WaitGroup
	label := p.probeLabel
	if label == "" {
		label = "--- LLM probe    "
	}
	fmt.Fprintf(os.Stderr, "%s %d candidates (%d templates)\n", label, len(candidates), p.engine.TemplateCount())
	progressWG.Add(1)
	go func() {
		defer progressWG.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n := done.Load()
				displayMu.Lock()
				fmt.Fprintf(os.Stderr, "\r      probing %d/%d ...", n, total)
				displayMu.Unlock()
			case <-stopProgress:
				displayMu.Lock()
				fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 40))
				displayMu.Unlock()
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	conc := p.cfg.MCPConcurrency
	if conc <= 0 {
		conc = 50
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []*models.LLMServer

	for _, cand := range candidates {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			goto done
		}
		wg.Add(1)
		go func(c HTTPCandidate) {
			defer wg.Done()
			defer func() { <-sem }()
			defer done.Add(1)
			defer func() {
				if rv := recover(); rv != nil {
					// Swallow panic — treat as failed candidate
				}
			}()

			scanDelay(p.cfg.DelayMs)

			candidateCtx, cancel := context.WithTimeout(ctx, llmCandidateTimeout(p.cfg))
			server := p.analyzeCandidate(candidateCtx, c)
			cancel()
			if server == nil {
				return
			}
			mu.Lock()
			results = append(results, server)
			mu.Unlock()
			if p.onFound != nil {
				displayMu.Lock()
				fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 40))
				p.onFound(server)
				displayMu.Unlock()
			}
		}(cand)
	}
done:
	wg.Wait()
	close(stopProgress)
	progressWG.Wait()

	fmt.Fprintf(os.Stderr, "      %d confirmed\n\n", len(results))

	// Sort by fingerprint score (highest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].FingerprintScore > results[j].FingerprintScore
	})

	return results
}

func (p *LLMPipeline) analyzeCandidate(ctx context.Context, c HTTPCandidate) *models.LLMServer {
	server := ProbeLLMWithHostname(ctx, p.engine, c.BaseURL, c.Hostname, p.cfg.TimeoutMCPMs)
	if server == nil {
		return nil
	}

	// Fill in candidate info
	server.IP = c.IP
	server.Port = c.Port
	server.Hostname = c.Hostname
	server.URL = c.BaseURL
	server.ScanTime = time.Now()

	return server
}

func llmCandidateTimeout(cfg models.ScanConfig) time.Duration {
	// LLM probes are lightweight GETs; use 5x connect timeout
	t := time.Duration(cfg.TimeoutConnectMs*5) * time.Millisecond
	if t < 5*time.Second {
		return 5 * time.Second
	}
	if t > 30*time.Second {
		return 30 * time.Second
	}
	return t
}

// RunLLMScan is the convenience entry point for the standalone `agentscan llm` command.
func RunLLMScan(ctx context.Context, rawTargets []string, filePath string,
	cfg models.ScanConfig, outputPath string, format string, noColor bool,
	templateDir string) ([]*models.LLMServer, error) {

	// Proxy
	netproxy.Configure(cfg.Proxy)

	// Parse targets
	var targets []target.Target
	if filePath != "" {
		ts, err := target.ParseFile(filePath, cfg.Ports)
		if err != nil {
			return nil, fmt.Errorf("parse file: %w", err)
		}
		targets = append(targets, ts...)
	}
	for _, raw := range rawTargets {
		ts, err := target.Parse(raw, cfg.Ports)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] skip %q: %v\n", raw, err)
			continue
		}
		targets = append(targets, ts...)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets; use -t <target>, positional arguments, or -f <file>")
	}
	targets, _ = dedupeTargets(targets)

	fmt.Fprintf(os.Stderr, "agentscan llm — %d target(s), %d port(s), %d thread(s)\n\n",
		len(targets), len(cfg.Ports), cfg.Concurrency)

	// Create pipeline
	var onFound func(*models.LLMServer)
	if format == "terminal" || format == "" {
		onFound = func(s *models.LLMServer) {
			output.PrintLLMServer(s, noColor)
		}
	}

	pipeline, err := NewLLMPipeline(cfg, noColor, onFound, templateDir)
	if err != nil {
		return nil, err
	}

	results := pipeline.Run(ctx, targets)

	// Summary
	if format == "terminal" || format == "" {
		output.PrintLLMSummary(results, noColor)
	}

	// JSON output
	if format == "json" || outputPath != "" {
		if err := output.WriteLLMJSON(results, outputPath); err != nil {
			return results, fmt.Errorf("write LLM JSON: %w", err)
		}
		if outputPath != "" {
			fmt.Fprintf(os.Stderr, "[*] LLM results written to: %s\n", outputPath)
		}
	}

	// HTML/TXT reports
	fmt.Fprintf(os.Stderr, "report     generating llm html/txt files...\n")
	reportDir, err := output.WriteLLMHTMLReports(results, htmlReportBaseDir(outputPath), rawTargets, filePath)
	if err != nil {
		return results, fmt.Errorf("write LLM HTML report: %w", err)
	}
	if reportDir != "" {
		fmt.Fprintf(os.Stderr, "report     %s\n", reportDir)
	}

	return results, nil
}
