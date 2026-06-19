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

	"github.com/agentscan/agentscan/pkg/analysis"
	"github.com/agentscan/agentscan/pkg/models"
	"github.com/agentscan/agentscan/pkg/output"
	"github.com/agentscan/agentscan/pkg/target"
)

// Pipeline 完整扫描流水线
type Pipeline struct {
	cfg     models.ScanConfig
	noColor bool
	onFound func(*models.MCPServer) // 实时回调
}

// NewPipeline 创建流水线
func NewPipeline(cfg models.ScanConfig, noColor bool, onFound func(*models.MCPServer)) *Pipeline {
	return &Pipeline{cfg: cfg, noColor: noColor, onFound: onFound}
}

func progressPercent(done, total int64) int {
	if total <= 0 {
		return 100
	}
	if done >= total {
		return 100
	}
	pct := int(float64(done) / float64(total) * 100)
	if pct >= 100 {
		return 99
	}
	return pct
}

func candidateTimeoutDuration(cfg models.ScanConfig) time.Duration {
	base := time.Duration(cfg.TimeoutMCPMs+cfg.TimeoutHTTPMs) * time.Millisecond
	if base < 8*time.Second {
		return 8 * time.Second
	}
	if base > 45*time.Second {
		return 45 * time.Second
	}
	return base
}

func slowCandidateThreshold(cfg models.ScanConfig) time.Duration {
	threshold := time.Duration(cfg.TimeoutMCPMs) * time.Millisecond
	if threshold < 5*time.Second {
		return 5 * time.Second
	}
	if threshold > 15*time.Second {
		return 15 * time.Second
	}
	return threshold
}

type slowTarget struct {
	Label    string
	Elapsed  time.Duration
	Hit      bool
	Endpoint string
}

func printSlowTargets(items []slowTarget) {
	if len(items) == 0 {
		return
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Elapsed > items[j].Elapsed
	})
	limit := len(items)
	if limit > 10 {
		limit = 10
	}
	fmt.Fprintf(os.Stderr, "slow targets (top %d/%d)\n", limit, len(items))
	for i := 0; i < limit; i++ {
		item := items[i]
		status := "miss"
		if item.Hit {
			status = "hit"
		}
		endpoint := item.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}
		fmt.Fprintf(os.Stderr, "      %-35s %6.1fs  %-4s %s\n",
			item.Label, item.Elapsed.Seconds(), status, endpoint)
	}
	fmt.Fprintf(os.Stderr, "\n")
}

// Run 执行完整扫描，返回所有结果（按风险分从高到低排序）
func (p *Pipeline) Run(ctx context.Context, targets []target.Target) []*models.MCPServer {
	// Stage 1: 端口扫描（--skip-port-scan 时跳过，所有输入视为已开放）
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
		portResults = ScanPorts(ctx, targets, p.cfg.Concurrency, p.cfg.TimeoutConnectMs, p.cfg.Verbose)
	}
	if len(portResults) == 0 {
		fmt.Fprintf(os.Stderr, "      no open ports found\n\n")
		return nil
	}

	// Stage 2: HTTP 筛选
	fmt.Fprintf(os.Stderr, "[2/3] http filter  %d ports\n", len(portResults))
	candidates := FilterHTTP(ctx, portResults, p.cfg.TimeoutHTTPMs)
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "      no HTTP services found\n\n")
		return nil
	}
	fmt.Fprintf(os.Stderr, "      %d candidates\n\n", len(candidates))

	total := int64(len(candidates))
	var done atomic.Int64
	var displayMu sync.Mutex

	stopProgress := make(chan struct{})
	var progressWG sync.WaitGroup
	fmt.Fprintf(os.Stderr, "[3/3] mcp probe    %d candidates\n", len(candidates))
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

	// Stage 4+5: MCP 识别 + 深度分析（并发）
	mcpConc := p.cfg.MCPConcurrency
	if mcpConc <= 0 {
		mcpConc = 50
	}
	sem := make(chan struct{}, mcpConc)
	var mu sync.Mutex
	var results []*models.MCPServer
	var slowMu sync.Mutex
	var slowTargets []slowTarget
	slowThreshold := slowCandidateThreshold(p.cfg)
	var wg sync.WaitGroup

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

			start := time.Now()
			candidateCtx, cancelCandidate := context.WithTimeout(ctx, candidateTimeoutDuration(p.cfg))
			server := p.analyzeCandidate(candidateCtx, c)
			cancelCandidate()
			elapsed := time.Since(start)

			if elapsed >= slowThreshold {
				label := fmt.Sprintf("%s:%d", c.IP, c.Port)
				if c.Hostname != "" {
					label = fmt.Sprintf("%s:%d", c.Hostname, c.Port)
				}
				st := slowTarget{Label: label, Elapsed: elapsed, Hit: server != nil}
				if server != nil {
					st.Endpoint = server.Endpoint
				}
				slowMu.Lock()
				slowTargets = append(slowTargets, st)
				slowMu.Unlock()
			}

			if server == nil {
				return
			}

			if p.cfg.ExcludeHoneypots && server.Honeypot.Suspected {
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
	printSlowTargets(slowTargets)

	// 按 FingerprintScore 从高到低排序
	sort.Slice(results, func(i, j int) bool {
		return results[i].FingerprintScore > results[j].FingerprintScore
	})
	return results
}

// analyzeCandidate 对单个候选目标完整分析（只做 MCP 存活识别，不做风险评估）
func (p *Pipeline) analyzeCandidate(ctx context.Context, c HTTPCandidate) *models.MCPServer {
	probe := ProbeMCPWithHostname(ctx, c.BaseURL, c.Hostname, c.URLPath, p.cfg.TimeoutMCPMs)
	if probe == nil || probe.FingerprintScore < 0.35 {
		return nil
	}

	server := &models.MCPServer{
		IP:               c.IP,
		Port:             c.Port,
		Hostname:         c.Hostname, // Bug2 fix: 传递域名，用于 JSON 输出和 SNI 可见性
		URL:              c.BaseURL,
		Endpoint:         probe.Endpoint,
		Transport:        probe.Transport,
		FingerprintScore: probe.FingerprintScore,
		SessionID:        probe.SessionID,
		ServerName:       probe.ServerName,
		ServerVersion:    probe.ServerVersion,
		ProtocolVersion:  probe.ProtocolVersion,
		NoAuth:           probe.NoAuth,
		AuthRequired:     probe.AuthRequired,
		ResponseTimeMs:   probe.ResponseTimeMs,
		TLSEnabled:       strings.HasPrefix(c.BaseURL, "https"), // Bug6 fix: 避免 magic length
		Evidence:         probe.Evidence,
		ScanTime:         time.Now(),
	}

	if p.cfg.VerboseRaw {
		server.RawInitResponse = probe.RawResponse
	}

	if probe.Capabilities != nil {
		for k := range probe.Capabilities {
			switch k {
			case "tools":
				server.Capabilities.Tools = probe.Capabilities[k]
			case "resources":
				server.Capabilities.Resources = probe.Capabilities[k]
			case "prompts":
				server.Capabilities.Prompts = probe.Capabilities[k]
			case "logging":
				server.Capabilities.Logging = probe.Capabilities[k]
			case "sampling": // Bug3 fix: 补全缺失的 capabilities
				server.Capabilities.Sampling = probe.Capabilities[k]
			case "completions":
				server.Capabilities.Completions = probe.Capabilities[k]
			case "experimental":
				server.Capabilities.Experimental = probe.Capabilities[k]
			}
		}
	}

	// auth-required：无法枚举工具或做蜜罐检测，直接返回
	if probe.AuthRequired {
		return server
	}

	// 枚举暴露面：tools / resources / resource templates / prompts
	var tools []models.MCPTool
	var resources []models.MCPResource
	var resourceTemplates []models.MCPResourceTemplate
	var prompts []models.MCPPrompt

	if probe.Transport == models.TransportHTTPSSELegacy {
		// SSE legacy：单次 session 枚举四类，避免四次独立握手
		tools, resources, resourceTemplates, prompts = EnumerateAllSSELegacy(ctx, c.BaseURL, probe.Endpoint, c.Hostname, p.cfg.TimeoutMCPMs)
	} else {
		// Streamable HTTP：四个独立请求复用同一 session（sessionID 传入）
		tools = EnumerateTools(ctx, c.BaseURL, probe.Endpoint, probe.MessagePath, probe.SessionID, c.Hostname, p.cfg.TimeoutMCPMs)
		resources = EnumerateResources(ctx, c.BaseURL, probe.Endpoint, probe.MessagePath, probe.SessionID, c.Hostname, p.cfg.TimeoutMCPMs)
		resourceTemplates = EnumerateResourceTemplates(ctx, c.BaseURL, probe.Endpoint, probe.MessagePath, probe.SessionID, c.Hostname, p.cfg.TimeoutMCPMs)
		prompts = EnumeratePrompts(ctx, c.BaseURL, probe.Endpoint, probe.MessagePath, probe.SessionID, c.Hostname, p.cfg.TimeoutMCPMs)
	}

	server.Tools = tools
	server.ToolCount = len(tools)
	server.Resources = resources
	server.ResourceCount = len(resources)
	server.ResourceTemplates = resourceTemplates
	server.ResourceTemplateCount = len(resourceTemplates)
	server.Prompts = prompts
	server.PromptCount = len(prompts)

	// 蜜罐检测（传入 hostname 确保 HTTPS SNI 正确，传入 messagePath 支持 SSE legacy）
	server.Honeypot = analysis.DetectHoneypot(ctx, server, c.Hostname, probe.MessagePath, p.cfg.TimeoutHTTPMs)

	return server
}

// RunScan 便捷入口：解析目标 + 运行流水线 + 实时打印
func RunScan(ctx context.Context, rawTargets []string, filePath string,
	cfg models.ScanConfig, outputPath string, format string, noColor bool) ([]*models.MCPServer, error) {

	// 收集所有目标
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

	// 统计唯一主机数（精确，适用于混合输入：CIDR + host:port + 域名）
	hostSet := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		hostSet[t.IP] = struct{}{}
	}
	hostCount := len(hostSet)

	if dupCount > 0 {
		fmt.Fprintf(os.Stderr, "           dedup: -%d  ->  %d targets\n", dupCount, len(targets))
	}

	// 大批量目标警告
	if len(targets) > 5000 {
		fmt.Fprintf(os.Stderr, "[!] large scan: %d probes\n", len(targets))
		if cfg.TimeoutConnectMs >= 1000 {
			fmt.Fprintf(os.Stderr, "    tip (intranet): --timeout 200 --threads 2000 --mcp-threads 200\n")
		}
		fmt.Fprintf(os.Stderr, "    tip (internet): --skip-port-scan for pre-scanned IP:port list\n\n")
	}

	// 构造端口列表字符串（超过 10 个省略）
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
	fmt.Fprintf(os.Stderr, "AgentScan  %d host(s)  %d port(s)  %d probe(s)\n",
		hostCount, len(cfg.Ports), len(targets))
	fmt.Fprintf(os.Stderr, "           ports=%s\n", portList)
	fmt.Fprintf(os.Stderr, "           threads=%d  connect-timeout=%dms  http-timeout=%dms  mcp-timeout=%dms  mcp-threads=%d%s\n",
		cfg.Concurrency, cfg.TimeoutConnectMs, cfg.TimeoutHTTPMs, cfg.TimeoutMCPMs, cfg.MCPConcurrency, skipStr)
	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "           output=%s\n", outputPath)
	}
	fmt.Fprintf(os.Stderr, "\n")

	// 实时打印回调
	var onFound func(*models.MCPServer)
	if format == "terminal" || format == "" {
		onFound = func(s *models.MCPServer) {
			output.PrintServer(s, noColor)
		}
	}

	pipeline := NewPipeline(cfg, noColor, onFound)
	results := pipeline.Run(ctx, targets)

	// 打印摘要
	if format == "terminal" || format == "" {
		output.PrintSummary(results, noColor)
	}

	// 输出 JSON
	if format == "json" || outputPath != "" {
		if err := output.WriteJSON(results, outputPath); err != nil {
			return results, fmt.Errorf("write JSON: %w", err)
		}
		if outputPath != "" {
			fmt.Fprintf(os.Stderr, "[*] Results written to: %s\n", outputPath)
		}
	}

	fmt.Fprintf(os.Stderr, "report     generating html/txt files...\n")
	reportDir, err := output.WriteHTMLReports(results, htmlReportBaseDir(outputPath))
	if err != nil {
		return results, fmt.Errorf("write HTML report: %w", err)
	}
	fmt.Fprintf(os.Stderr, "report     %s\n", reportDir)

	return results, nil
}

type targetKey struct {
	ip       string
	port     int
	hostname string
	urlPath  string
	proto    string
}

func dedupeTargets(targets []target.Target) ([]target.Target, int) {
	seen := make(map[targetKey]struct{}, len(targets))
	deduped := make([]target.Target, 0, len(targets))
	for _, t := range targets {
		key := targetKey{
			ip:       t.IP,
			port:     t.Port,
			hostname: t.Hostname,
			urlPath:  t.URLPath,
			proto:    t.Proto,
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, t)
	}
	return deduped, len(targets) - len(deduped)
}

func htmlReportBaseDir(outputPath string) string {
	if outputPath == "" || outputPath == "-" {
		return "."
	}
	dir := filepath.Dir(outputPath)
	if dir == "" {
		return "."
	}
	return dir
}
