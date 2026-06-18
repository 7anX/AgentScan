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

// Run 执行完整扫描，返回所有结果（按风险分从高到低排序）
func (p *Pipeline) Run(ctx context.Context, targets []target.Target) []*models.MCPServer {
	// Stage 1: 端口扫描（--skip-port-scan 时跳过，所有输入视为已开放）
	var portResults []PortResult
	if p.cfg.SkipPortScan {
		fmt.Fprintf(os.Stderr, "[*] Stage 1/3  TCP port scan: SKIPPED (--skip-port-scan)\n")
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
		fmt.Fprintf(os.Stderr, "[!] No open ports found, exiting.\n")
		return nil
	}

	// Stage 3: HTTP 筛选（并发）
	fmt.Fprintf(os.Stderr, "[*] Stage 2/3  HTTP filter: checking %d open ports (timeout=%dms)\n",
		len(portResults), p.cfg.TimeoutHTTPMs)
	candidates := FilterHTTP(ctx, portResults, p.cfg.TimeoutHTTPMs)
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "[!] No HTTP services found, exiting.\n")
		return nil
	}
	fmt.Fprintf(os.Stderr, "[*] Stage 2/3  HTTP filter done: %d HTTP candidates\n", len(candidates))

	total := int64(len(candidates))
	var done atomic.Int64

	// 进度打印 goroutine：每秒在 stderr 打印一次进度（含当前目标）
	type probeStatus struct {
		mu      sync.Mutex
		current string
	}
	var ps probeStatus

	stopProgress := make(chan struct{})
	fmt.Fprintf(os.Stderr, "[*] Stage 3/3  MCP probe: %d candidates\n", len(candidates))
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n := done.Load()
				ps.mu.Lock()
				cur := ps.current
				ps.mu.Unlock()
				if cur != "" {
					fmt.Fprintf(os.Stderr, "\r[*] Probing MCP: %d/%d (%.0f%%)  -> %-40s",
						n, total, float64(n)/float64(total)*100, cur)
				} else {
					fmt.Fprintf(os.Stderr, "\r[*] Probing MCP: %d/%d (%.0f%%)   ",
						n, total, float64(n)/float64(total)*100)
				}
			case <-stopProgress:
				fmt.Fprintf(os.Stderr, "\r[*] Probing MCP: %d/%d done%s\n", total, total, "            ")
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

			// 更新当前探测目标
			label := fmt.Sprintf("%s:%d", c.IP, c.Port)
			if c.Hostname != "" {
				label = fmt.Sprintf("%s:%d", c.Hostname, c.Port)
			}
			ps.mu.Lock()
			ps.current = label
			ps.mu.Unlock()

			var t0 time.Time
			if p.cfg.Verbose {
				t0 = time.Now()
				fmt.Fprintf(os.Stderr, "\n  [PROBE] %s%s\n", c.BaseURL, c.URLPath)
			}

			server := p.analyzeCandidate(ctx, c)

			if p.cfg.Verbose {
				elapsed := time.Since(t0)
				if server != nil {
					fmt.Fprintf(os.Stderr, "  [HIT]   %-35s  server=%q  tools=%d  (%dms)\n",
						label, server.ServerName, server.ToolCount, elapsed.Milliseconds())
				} else {
					fmt.Fprintf(os.Stderr, "  [MISS]  %-35s  (%dms)\n", label, elapsed.Milliseconds())
				}
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
				p.onFound(server)
			}
		}(cand)
	}
done:
	wg.Wait()
	close(stopProgress)

	fmt.Fprintf(os.Stderr, "[*] Stage 3/3  MCP probe done: %d confirmed MCP servers\n", len(results))

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

	// 去重：同一 IP:Port:URLPath 只扫一次。
	// URLPath 必须参与 key：http://IP:8080/mcp 和 http://IP:8080/api/mcp 是不同扫描目标。
	type ipPortPath struct {
		ip      string
		port    int
		urlPath string
	}
	seen := make(map[ipPortPath]struct{}, len(targets))
	deduped := make([]target.Target, 0, len(targets)) // 独立 slice，不共享底层数组
	for _, t := range targets {
		key := ipPortPath{t.IP, t.Port, t.URLPath}
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			deduped = append(deduped, t)
		}
	}
	dupCount := len(targets) - len(deduped)
	targets = deduped

	// 统计唯一主机数（精确，适用于混合输入：CIDR + host:port + 域名）
	hostSet := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		hostSet[t.IP] = struct{}{}
	}
	hostCount := len(hostSet)

	if dupCount > 0 {
		fmt.Fprintf(os.Stderr, "[*] Deduplicated %d duplicate targets\n", dupCount)
	}

	// 大批量目标警告：超过 5000 时提示推荐参数
	if len(targets) > 5000 {
		fmt.Fprintf(os.Stderr, "[!] Large scan: %d probes detected.\n", len(targets))
		if cfg.TimeoutConnectMs >= 1000 {
			fmt.Fprintf(os.Stderr, "[!]   Tip (intranet): use --timeout 200 --threads 2000 --mcp-threads 200 for faster results\n")
		}
		fmt.Fprintf(os.Stderr, "[!]   Tip (internet): use --skip-port-scan if feeding pre-scanned IP:Port list\n")
	}

	fmt.Fprintf(os.Stderr, "[*] AgentScan starting: %d hosts × %d ports = %d probes\n",
		hostCount, len(cfg.Ports), len(targets))
	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "[*] Output file: %s\n", outputPath)
	}
	fmt.Fprintf(os.Stderr, "[*] Config: threads=%d  connect-timeout=%dms  mcp-threads=%d%s\n",
		cfg.Concurrency, cfg.TimeoutConnectMs, cfg.MCPConcurrency,
		map[bool]string{true: "  skip-port-scan=true", false: ""}[cfg.SkipPortScan])

	// 实时打印回调
	onFound := func(s *models.MCPServer) {
		output.PrintServer(s, noColor)
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

	return results, nil
}
