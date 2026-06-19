package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentscan/agentscan/pkg/models"
	"github.com/agentscan/agentscan/pkg/netproxy"
	"github.com/agentscan/agentscan/pkg/output"
	"github.com/agentscan/agentscan/pkg/target"
)

type A2APipeline struct {
	cfg             models.ScanConfig
	noColor         bool
	includeProbable bool
	probeLabel      string // printed as the stage header in RunFromCandidates
	onFound         func(*models.A2AServer)
}

func NewA2APipeline(cfg models.ScanConfig, noColor bool, includeProbable bool, onFound func(*models.A2AServer)) *A2APipeline {
	return &A2APipeline{cfg: cfg, noColor: noColor, includeProbable: includeProbable, probeLabel: "[3/3] a2a probe   ", onFound: onFound}
}

func (p *A2APipeline) Run(ctx context.Context, targets []target.Target) []*models.A2AServer {
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

	fmt.Fprintf(os.Stderr, "[2/3] http filter  %d ports\n", len(portResults))
	candidates := FilterHTTP(ctx, portResults, p.cfg.TimeoutHTTPMs, p.cfg.Concurrency, p.cfg.Dict)
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "      no HTTP services found\n\n")
		return nil
	}
	fmt.Fprintf(os.Stderr, "      %d candidates\n\n", len(candidates))

	return p.RunFromCandidates(ctx, candidates)
}

// RunFromCandidates runs A2A probes against already-filtered HTTP candidates.
// Used by agentscan scan to share port scan and HTTP filter results with MCP.
func (p *A2APipeline) RunFromCandidates(ctx context.Context, candidates []HTTPCandidate) []*models.A2AServer {
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
		label = "[3/3] a2a probe   "
	}
	fmt.Fprintf(os.Stderr, "%s %d candidates\n", label, len(candidates))
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
	var results []*models.A2AServer

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

			scanDelay(p.cfg.DelayMs)

			candidateCtx, cancel := context.WithTimeout(ctx, a2aCandidateTimeout(p.cfg))
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
	sort.Slice(results, func(i, j int) bool {
		return results[i].FingerprintScore > results[j].FingerprintScore
	})
	return results
}

// a2aCandidateTimeout returns a per-candidate context deadline for A2A probing.
// Unlike MCP, A2A only needs TimeoutMCPMs (card fetch + 1-2 JSON-RPC calls).
// TimeoutHTTPMs is the HTTP filter timeout and does not apply here.
func a2aCandidateTimeout(cfg models.ScanConfig) time.Duration {
	t := time.Duration(cfg.TimeoutMCPMs) * time.Millisecond
	if t < 5*time.Second {
		return 5 * time.Second
	}
	if t > 20*time.Second {
		return 20 * time.Second
	}
	return t
}

func (p *A2APipeline) analyzeCandidate(ctx context.Context, c HTTPCandidate) *models.A2AServer {
	probe := ProbeA2AWithHostname(ctx, c.BaseURL, c.Hostname, c.URLPath, p.cfg.TimeoutMCPMs, p.includeProbable, p.cfg.Dict)
	if probe == nil {
		return nil
	}
	if !probe.A2AConfirmed && !p.includeProbable {
		return nil
	}

	server := &models.A2AServer{
		IP:               c.IP,
		Port:             c.Port,
		Hostname:         c.Hostname,
		URL:              c.BaseURL,
		CardURL:          probe.CardURL,
		CardPath:         probe.CardPath,
		Profile:          probe.Profile,
		ExposureStatus:   probe.ExposureStatus,
		ExposureSignals:  probe.ExposureSignals,
		A2AConfirmed:     probe.A2AConfirmed,
		FingerprintScore: probe.FingerprintScore,
		NoAuth:           probe.NoAuth,
		AuthRequired:     probe.AuthRequired,
		EndpointDisabled: probe.EndpointDisabled,
		AgentName:        probe.AgentName,
		Description:      probe.Description,
		Version:          probe.Version,
		ProtocolVersion:  probe.ProtocolVersion,
		Provider:         probe.Provider,
		Capabilities:     probe.Capabilities,
		Skills:           probe.Skills,
		SkillCount:       len(probe.Skills),
		Interfaces:       probe.Interfaces,
		ScanTime:         time.Now(),
		ResponseTimeMs:   probe.ResponseTimeMs,
		TLSEnabled:       strings.HasPrefix(c.BaseURL, "https"),
		Evidence:         probe.Evidence,
	}
	if p.cfg.VerboseRaw {
		server.RawCardResponse = probe.RawCard
	}
	return server
}

func RunA2AScan(ctx context.Context, rawTargets []string, filePath string,
	cfg models.ScanConfig, outputPath string, format string, noColor bool, includeProbable bool) ([]*models.A2AServer, error) {
	if err := netproxy.Configure(cfg.Proxy); err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}

	var targets []target.Target
	if filePath != "" {
		fmt.Fprintf(os.Stderr, "[*] Loading targets from file: %s\n", filePath)
		ts, err := target.ParseFile(filePath, cfg.Ports)
		if err != nil {
			return nil, fmt.Errorf("parse file: %w", err)
		}
		targets = append(targets, ts...)
		fmt.Fprintf(os.Stderr, "[*] Loaded %d targets from file\n", len(ts))
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
		return nil, fmt.Errorf("no valid targets")
	}
	deduped, dupCount := dedupeTargets(targets)
	targets = deduped

	hostSet := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		hostSet[t.IP] = struct{}{}
	}
	if dupCount > 0 {
		fmt.Fprintf(os.Stderr, "           dedup: -%d  ->  %d targets\n", dupCount, len(targets))
	}

	portStrs := make([]string, len(cfg.Ports))
	for i, p := range cfg.Ports {
		portStrs[i] = fmt.Sprintf("%d", p)
	}
	portList := strings.Join(portStrs, ",")
	if len(cfg.Ports) > 10 {
		portList = strings.Join(portStrs[:10], ",") + fmt.Sprintf(",...(%d)", len(cfg.Ports))
	}
	skipStr := ""
	if cfg.SkipPortScan {
		skipStr = "  skip-port-scan"
	}
	proxyStr := ""
	if cfg.Proxy != "" {
		proxyStr = "  proxy=" + cfg.Proxy
	}
	fmt.Fprintf(os.Stderr, "AgentScan A2A  %d host(s)  %d port(s)  %d probe(s)\n", len(hostSet), len(cfg.Ports), len(targets))
	fmt.Fprintf(os.Stderr, "               ports=%s\n", portList)
	fmt.Fprintf(os.Stderr, "               threads=%d  connect-timeout=%dms  http-timeout=%dms  a2a-timeout=%dms  a2a-threads=%d%s%s\n",
		cfg.Concurrency, cfg.TimeoutConnectMs, cfg.TimeoutHTTPMs, cfg.TimeoutMCPMs, cfg.MCPConcurrency, skipStr, proxyStr)
	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "               output=%s\n", outputPath)
	}
	fmt.Fprintf(os.Stderr, "\n")

	var onFound func(*models.A2AServer)
	if format == "terminal" || format == "" {
		onFound = func(s *models.A2AServer) {
			output.PrintA2AServer(s, noColor)
		}
	}
	pipeline := NewA2APipeline(cfg, noColor, includeProbable, onFound)
	results := pipeline.Run(ctx, targets)
	if format == "terminal" || format == "" {
		output.PrintA2ASummary(results, noColor)
	}
	if format == "json" || outputPath != "" {
		if err := output.WriteA2AJSON(results, outputPath); err != nil {
			return results, fmt.Errorf("write JSON: %w", err)
		}
		if outputPath != "" {
			fmt.Fprintf(os.Stderr, "[*] Results written to: %s\n", outputPath)
		}
	}
	fmt.Fprintf(os.Stderr, "report     generating html/txt files...\n")
	reportDir, err := output.WriteA2AHTMLReports(results, htmlA2AReportBaseDir(outputPath), rawTargets, filePath)
	if err != nil {
		return results, fmt.Errorf("write A2A HTML report: %w", err)
	}
	fmt.Fprintf(os.Stderr, "report     %s\n", reportDir)
	return results, nil
}

func htmlA2AReportBaseDir(outputPath string) string {
	if outputPath == "" {
		return "."
	}
	return filepath.Dir(outputPath)
}
