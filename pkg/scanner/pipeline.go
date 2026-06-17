package scanner

import (
	"context"
	"fmt"
	"os"
	"sort"
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
	// Stage 2: 端口扫描
	portResults := ScanPorts(ctx, targets, p.cfg.Concurrency, p.cfg.TimeoutConnectMs)
	if len(portResults) == 0 {
		return nil
	}

	// Stage 3: HTTP 筛选（并发）
	candidates := FilterHTTP(ctx, portResults, p.cfg.TimeoutHTTPMs)
	if len(candidates) == 0 {
		return nil
	}

	total := int64(len(candidates))
	var done atomic.Int64

	// 进度打印 goroutine：每秒在 stderr 打印一次进度
	stopProgress := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n := done.Load()
				fmt.Fprintf(os.Stderr, "\r[*] Probing MCP: %d/%d candidates (%.0f%%)   ",
					n, total, float64(n)/float64(total)*100)
			case <-stopProgress:
				fmt.Fprintf(os.Stderr, "\r[*] Probing MCP: %d/%d done%s\n", total, total, "            ")
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Stage 4+5: MCP 识别 + 深度分析（并发）
	sem := make(chan struct{}, 50)
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

			server := p.analyzeCandidate(ctx, c)
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
		URL:              c.BaseURL,
		Endpoint:         probe.Endpoint,
		Transport:        probe.Transport,
		FingerprintScore: probe.FingerprintScore,
		SessionID:        probe.SessionID,
		ServerName:       probe.ServerName,
		ServerVersion:    probe.ServerVersion,
		ProtocolVersion:  probe.ProtocolVersion,
		NoAuth:           probe.NoAuth,
		ResponseTimeMs:   probe.ResponseTimeMs,
		TLSEnabled:       len(c.BaseURL) > 5 && c.BaseURL[:5] == "https",
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
			}
		}
	}

	// 工具枚举
	tools := EnumerateTools(ctx, c.BaseURL, probe.Endpoint, probe.SessionID, c.Hostname, p.cfg.TimeoutMCPMs)
	server.Tools = tools
	server.ToolCount = len(tools)

	// 蜜罐检测（传入 hostname 确保 HTTPS SNI 正确）
	server.Honeypot = analysis.DetectHoneypot(ctx, server, c.Hostname, p.cfg.TimeoutHTTPMs)

	return server
}

// RunScan 便捷入口：解析目标 + 运行流水线 + 实时打印
func RunScan(ctx context.Context, rawTargets []string, filePath string,
	cfg models.ScanConfig, outputPath string, format string, noColor bool) ([]*models.MCPServer, error) {

	// 收集所有目标
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
		return nil, fmt.Errorf("no valid targets")
	}

	// 去重：同一 IP:Port 只扫一次（用 struct key 避免 Sprintf 分配）
	type ipPort struct{ ip string; port int }
	seen := make(map[ipPort]struct{}, len(targets))
	deduped := make([]target.Target, 0, len(targets)) // 独立 slice，不共享底层数组
	for _, t := range targets {
		key := ipPort{t.IP, t.Port}
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			deduped = append(deduped, t)
		}
	}
	targets = deduped

	// 统计唯一主机数（精确，适用于混合输入：CIDR + host:port + 域名）
	hostSet := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		hostSet[t.IP] = struct{}{}
	}
	hostCount := len(hostSet)
	fmt.Fprintf(os.Stderr, "[*] AgentScan starting: %d hosts × %d ports = %d probes\n",
		hostCount, len(cfg.Ports), len(targets))

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
	}

	return results, nil
}
