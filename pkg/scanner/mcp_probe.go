package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agentscan/agentscan/internal/sseutil"
	"github.com/agentscan/agentscan/pkg/config"
	"github.com/agentscan/agentscan/pkg/models"
)

// MCP 特有 capabilities key（区别于 LSP）
var mcpCapKeys = map[string]bool{
	"tools": true, "resources": true, "prompts": true,
	"logging": true, "sampling": true, "completions": true,
}

// LSP 特有 key（出现则直接排除）
var lspCapKeys = map[string]bool{
	"textDocumentSync": true, "hoverProvider": true,
	"completionProvider": true, "definitionProvider": true,
	"referencesProvider": true, "documentSymbolProvider": true,
}

// 预计算 initialize 请求体，避免每次探测都 json.Marshal
var (
	initBodyStreamable = mustBuildInit("2025-06-18")
	initBodyLegacy     = mustBuildInit("2024-11-05")
	initBodyInvalid    = mustBuildInit("9999-99-99") // 蜜罐探针专用
)

func mustBuildInit(version string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": version,
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "mcp-client",
				"version": "1.0.0",
			},
		},
	})
	return b
}

// initializeRequest 构造 MCP initialize 请求体（优先使用预计算版本）
func initializeRequest(version string) []byte {
	switch version {
	case "2025-06-18":
		return initBodyStreamable
	case "2024-11-05":
		return initBodyLegacy
	case "9999-99-99":
		return initBodyInvalid
	default:
		return mustBuildInit(version)
	}
}

// ProbeResult MCP 探测结果
type ProbeResult struct {
	Endpoint         string
	Transport        models.Transport
	FingerprintScore float64
	SessionID        string
	ProtocolVersion  string
	ServerName       string
	ServerVersion    string
	Capabilities     map[string]interface{}
	RawResponse      json.RawMessage
	Evidence         models.MCPEvidence
	NoAuth           bool
	AuthRequired     bool // MCP 服务器存在但需要认证
	ResponseTimeMs   float64
	// MessagePath 仅 SSE legacy transport 有效：GET /sse 拿到的 POST endpoint 路径
	// （如 /mcp/v1/basic/message/?session_id=xxx），用于后续 tools/list 等请求
	MessagePath string
}

// ProbeMCP 对单个 base URL 尝试识别 MCP 服务
// hostname 用于 HTTPS SNI，为空时从 baseURL 中提取
func ProbeMCP(ctx context.Context, baseURL string, timeoutMs int) *ProbeResult {
	return ProbeMCPWithHostname(ctx, baseURL, "", "", timeoutMs, nil)
}

// ProbeMCPWithHostname 支持指定 hostname（SNI）和 urlPath（优先端点）的 MCP 探测
// dict 为字典集合；传 nil 时使用 config.DefaultDictSet()。
func ProbeMCPWithHostname(ctx context.Context, baseURL, hostname, urlPath string, timeoutMs int, dict *config.DictSet) *ProbeResult {
	if dict == nil {
		dict = config.DefaultDictSet()
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := buildHTTPClient(hostname, timeout)

	endpoints := buildProbeEndpoints(urlPath, dict)

	// 并行探测所有端点，找到第一个无认证命中立即返回
	// 使用可取消的 context：一旦找到结果，取消所有其他 goroutine
	probeCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	type result struct {
		r        *ProbeResult
		priority int // 越小越优先（端点在列表中的位置）
	}

	resultCh := make(chan result, len(endpoints)+len(endpoints)) // 留足缓冲
	var wg sync.WaitGroup

	for i, endpoint := range endpoints {
		wg.Add(1)
		go func(ep string, priority int) {
			defer wg.Done()
			url := baseURL + ep

			r := tryStreamableHTTP(probeCtx, client, url, ep, dict.MCPAuthPaths)
			if r != nil {
				r.Endpoint = ep
				resultCh <- result{r, priority}
				return
			}

			// 判断是否应尝试 SSE legacy：
			// 1. 固定路径表命中（/sse、/mcp/sse 等）
			// 2. 路径以 /sse 或 /sse/ 结尾（兼容自定义前缀，如 /9da4ht4y/sse）
			// 3. 以上都不满足时，做一次轻量 GET 探测：若响应 Content-Type 是
			//    text/event-stream，则这是一个 SSE endpoint（路径名不含 "sse" 也能识别）
			isSSEPath := dict.SSELegacyPaths[ep] ||
				strings.HasSuffix(ep, "/sse") ||
				strings.HasSuffix(ep, "/sse/")
			if !isSSEPath {
				isSSEPath = isSSEEndpoint(probeCtx, client, url)
			}
			if isSSEPath {
				if r := tryHTTPSSELegacy(probeCtx, client, baseURL, ep, timeout); r != nil {
					r.Endpoint = ep
					resultCh <- result{r, priority}
				}
			}
		}(endpoint, i)
	}

	// 关闭 channel：所有 goroutine 完成后
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 收集结果：优先返回 no-auth，其次返回 auth-required
	var bestNoAuth *ProbeResult
	var bestNoAuthPriority = int(^uint(0) >> 1) // MaxInt
	var bestAuthRequired *ProbeResult
	var bestAuthPriority = int(^uint(0) >> 1)

	for resultCh != nil {
		select {
		case res, ok := <-resultCh:
			if !ok {
				resultCh = nil
				break
			}
			if !res.r.AuthRequired {
				if res.priority < bestNoAuthPriority {
					bestNoAuth = res.r
					bestNoAuthPriority = res.priority
				}
				if res.r.FingerprintScore >= 0.55 {
					cancelAll()
					return res.r
				}
				if res.priority == 0 {
					cancelAll()
					return bestNoAuth
				}
			} else {
				if res.priority < bestAuthPriority {
					bestAuthRequired = res.r
					bestAuthPriority = res.priority
				}
			}
		case <-probeCtx.Done():
			if bestNoAuth != nil {
				return bestNoAuth
			}
			return bestAuthRequired
		}
	}

	if bestNoAuth != nil {
		return bestNoAuth
	}
	return bestAuthRequired
}

func buildProbeEndpoints(urlPath string, dict *config.DictSet) []string {
	if dict == nil {
		dict = config.DefaultDictSet()
	}
	if urlPath == "" || urlPath == "/" {
		return dict.MCPEndpoints
	}

	seen := make(map[string]struct{}, len(dict.MCPEndpoints)*2)
	endpoints := make([]string, 0, len(dict.MCPEndpoints)*2)
	add := func(ep string) {
		ep = normalizeProbeEndpoint(ep)
		if ep == "" {
			return
		}
		if _, ok := seen[ep]; ok {
			return
		}
		seen[ep] = struct{}{}
		endpoints = append(endpoints, ep)
	}

	normalized := normalizeProbeEndpoint(urlPath)
	add(normalized)

	if shouldExpandMountPrefix(urlPath) {
		prefix := strings.TrimRight(normalized, "/")
		for _, ep := range dict.MCPEndpoints {
			if ep == "/" {
				add(prefix)
				continue
			}
			add(prefix + "/" + strings.TrimLeft(ep, "/"))
		}
	}

	for _, ep := range dict.MCPEndpoints {
		add(ep)
	}
	return endpoints
}

func normalizeProbeEndpoint(ep string) string {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return ""
	}
	if !strings.HasPrefix(ep, "/") {
		ep = "/" + ep
	}
	return ep
}

func shouldExpandMountPrefix(urlPath string) bool {
	if strings.HasSuffix(urlPath, "/") {
		return true
	}
	last := urlPath
	if i := strings.LastIndex(last, "/"); i >= 0 {
		last = last[i+1:]
	}
	switch strings.ToLower(last) {
	case "mcp", "sse", "message", "messages", "health", "server-card.json":
		return false
	default:
		return true
	}
}

// isSSEEndpoint 做一次轻量 GET 探测，判断 url 是否返回 text/event-stream。
// 用于识别路径名不含 "sse" 关键词的 SSE endpoint（如 /abc123/ 或 /v2/stream）。
// 只读响应头，不消费 body，超时 2s。
func isSSEEndpoint(ctx context.Context, client *http.Client, url string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
}

// tryStreamableHTTP POST /mcp 尝试 Streamable HTTP（2025-03-26+）

func sseProbeSessionTimeout(timeout time.Duration) time.Duration {
	d := timeout * 2
	if d < 5*time.Second {
		return 5 * time.Second
	}
	if d > 12*time.Second {
		return 12 * time.Second
	}
	return d
}

// endpoint 参数用于辅助 auth-required 判断（/mcp、/sse 等 MCP 特征路径名）
func tryStreamableHTTP(ctx context.Context, client *http.Client, url, endpoint string, authPaths map[string]bool) *ProbeResult {
	// 单个端点探测最多等 3 秒，避免 20 个端点串行时总超时爆炸
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	body := initializeRequest("2025-06-18")

	req, err := http.NewRequestWithContext(probeCtx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", config.UserAgent)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	elapsed := float64(time.Since(start).Milliseconds())
	headers := relevantHeaders(resp.Header)

	if resp.StatusCode != 200 {
		// 检测是否为需要认证的 MCP 服务器（三个条件同时满足才报告，避免误报）：
		// 1. 状态码明确表示认证失败（401/403），或 400 且带 WWW-Authenticate
		// 2. 响应体包含 "jsonrpc" 字段（JSON-RPC 协议特征）
		// 3. 响应体包含 "error" 字段，或响应头有 MCP-Session-Id / MCP-Protocol-Version
		authRequired, authEvidence := isMCPAuthRequiredWithEvidence(resp, endpoint, authPaths)
		if authRequired {
			return &ProbeResult{
				Transport:        models.TransportStreamableHTTP,
				FingerprintScore: 0.5, // 固定中间分：确认是 MCP，但无法完整指纹
				NoAuth:           false,
				AuthRequired:     true,
				ResponseTimeMs:   elapsed,
				Evidence: models.MCPEvidence{
					URL:             url,
					Transport:       models.TransportStreamableHTTP,
					ResponseHeaders: headers,
					JSONRPC: models.JSONRPCSummary{
						RequestMethod: "initialize",
						StatusCode:    resp.StatusCode,
						ContentType:   resp.Header.Get("Content-Type"),
					},
					Fingerprint: models.FingerprintEvidence{
						Score:   0.5,
						Signals: []string{"auth_required_mcp_signals"},
					},
					Auth:           authEvidence,
					ResponseTimeMs: elapsed,
				},
			}
		}
		return nil
	}

	ct := resp.Header.Get("Content-Type")
	var data map[string]interface{}

	// 规范允许两种响应形式，都要处理
	if strings.Contains(ct, "text/event-stream") {
		data = sseutil.ParseFirstMessage(io.LimitReader(resp.Body, 2<<20)) // 2MB 上限防止恶意服务器无限流
	} else {
		limitedBody := io.LimitReader(resp.Body, 1<<20) // 1MB
		if err := json.NewDecoder(limitedBody).Decode(&data); err != nil {
			// decode 失败，但如果有 MCP 专有响应头，说明服务存在（宁可误报不漏）
			if resp.Header.Get("Mcp-Session-Id") != "" || resp.Header.Get("Mcp-Protocol-Version") != "" {
				protocolVersion := resp.Header.Get("Mcp-Protocol-Version")
				return &ProbeResult{
					Transport:        models.TransportStreamableHTTP,
					FingerprintScore: 0.4,
					SessionID:        resp.Header.Get("Mcp-Session-Id"),
					ProtocolVersion:  protocolVersion,
					NoAuth:           true,
					AuthRequired:     false,
					ResponseTimeMs:   elapsed,
					Evidence: models.MCPEvidence{
						URL:             url,
						Transport:       models.TransportStreamableHTTP,
						ProtocolVersion: protocolVersion,
						ResponseHeaders: headers,
						JSONRPC: models.JSONRPCSummary{
							RequestMethod: "initialize",
							StatusCode:    resp.StatusCode,
							ContentType:   resp.Header.Get("Content-Type"),
						},
						Fingerprint: models.FingerprintEvidence{
							Score:   0.4,
							Signals: []string{"mcp_response_header"},
						},
						Auth:           models.AuthEvidence{Status: "no-auth", Reasons: []string{"initialize endpoint responded without an auth challenge"}},
						ResponseTimeMs: elapsed,
					},
				}
			}
			return nil
		}
	}

	if data == nil {
		return nil
	}

	score, serverName, serverVer, protocolVer, caps, fingerprint := scoreFingerprintDetailed(data)
	if score < 0.35 {
		return nil // 太低，跳过
	}
	fingerprint.Score = score

	return &ProbeResult{
		Transport:        models.TransportStreamableHTTP,
		FingerprintScore: score,
		SessionID:        resp.Header.Get("Mcp-Session-Id"),
		ServerName:       serverName,
		ServerVersion:    serverVer,
		ProtocolVersion:  protocolVer,
		Capabilities:     caps,
		RawResponse:      marshalRaw(data),
		NoAuth:           true, // 能连上且无认证头
		ResponseTimeMs:   elapsed,
		Evidence: models.MCPEvidence{
			URL:             url,
			Transport:       models.TransportStreamableHTTP,
			ProtocolVersion: protocolVer,
			ResponseHeaders: headers,
			JSONRPC:         summarizeJSONRPC("initialize", resp.StatusCode, resp.Header.Get("Content-Type"), data),
			Fingerprint:     fingerprint,
			Auth:            models.AuthEvidence{Status: "no-auth", Reasons: []string{"initialize returned a valid MCP JSON-RPC result without auth challenge"}},
			ResponseTimeMs:  elapsed,
		},
	}
}

// tryHTTPSSELegacy 旧版 HTTP+SSE（2024-11-05）
// 正确实现：保持 GET <ssePath> 连接不关闭，并行 POST，从 SSE 流读响应。
// 这是 SSE legacy 的核心协议要求：session 与连接绑定，断开连接即 session 失效。
// ssePath 是实际的 SSE GET 路径（如 /sse、/mcp/sse、/mcp-server/sse、/sse/），不再硬编码。
func tryHTTPSSELegacy(ctx context.Context, client *http.Client, baseURL, ssePath string, timeout time.Duration) *ProbeResult {
	// 整个 SSE 会话使用独立超时，并跟随外层 ctx 取消。
	// 12s：GET握手(~1s) + endpoint event(~1s) + POST(~1s) + SSE message回推(~3s) + 跨国链路余量
	sessCtx, sessCancel := context.WithTimeout(ctx, sseProbeSessionTimeout(timeout))
	defer sessCancel()

	// Step 1: 建立 SSE 连接并启动监听 goroutine
	sseReq, err := http.NewRequestWithContext(sessCtx, "GET", baseURL+ssePath, nil)
	if err != nil {
		return nil
	}
	sseReq.Header.Set("Accept", "text/event-stream")

	sseResp, err := client.Do(sseReq)
	if err != nil {
		return nil
	}
	defer sseResp.Body.Close()

	if sseResp.StatusCode != 200 {
		// SSE GET 被拒绝（401/403）→ 可能是需要认证的 SSE legacy 服务
		if sseResp.StatusCode == 401 || sseResp.StatusCode == 403 {
			headers := relevantHeaders(sseResp.Header)
			io.Copy(io.Discard, io.LimitReader(sseResp.Body, 4096)) //nolint:errcheck
			return &ProbeResult{
				Transport:        models.TransportHTTPSSELegacy,
				FingerprintScore: 0.5,
				NoAuth:           false,
				AuthRequired:     true,
				Evidence: models.MCPEvidence{
					URL:             baseURL + ssePath,
					Transport:       models.TransportHTTPSSELegacy,
					ResponseHeaders: headers,
					JSONRPC: models.JSONRPCSummary{
						RequestMethod: "sse-connect",
						StatusCode:    sseResp.StatusCode,
						ContentType:   sseResp.Header.Get("Content-Type"),
					},
					Fingerprint: models.FingerprintEvidence{
						Score:   0.5,
						Signals: []string{"sse_endpoint_auth_challenge"},
					},
					Auth: models.AuthEvidence{
						Status:  "auth-required",
						Reasons: []string{fmt.Sprintf("SSE endpoint returned HTTP %d", sseResp.StatusCode)},
					},
				},
			}
		}
		return nil
	}

	// 启动 SSE 监听 goroutine
	postPathCh := make(chan string, 1)
	msgCh := make(chan map[string]interface{}, 8)
	go sseutil.ParseEndpointAndListen(sseResp.Body, postPathCh, msgCh)

	// Step 2: 等待 endpoint event，拿到 postPath
	var postPath string
	select {
	case postPath = <-postPathCh:
	case <-sessCtx.Done():
		return nil
	}

	if postPath == "" {
		return nil
	}
	if !strings.HasPrefix(postPath, "/") || strings.Contains(postPath, "..") || strings.Contains(postPath, "://") {
		return nil
	}

	// Step 3: POST initialize（在 sessCtx 内，session 仍然有效）
	//
	// 反向代理场景修正：服务器返回的 endpoint path 可能是不含代理前缀的绝对路径。
	// 例如 SSE 路径为 /9da4ht4y/sse，服务器返回 data: /messages/?session_id=xxx，
	// 此时直接拼 baseURL+postPath = host/messages/ 会 502。
	// 修正：若 ssePath 有多层前缀（/prefix/sse），而 postPath 不以该前缀开头，
	// 则尝试用 ssePath 的父目录前缀拼接。
	resolvedPostPath := postPath
	sseDir := ssePath[:strings.LastIndex(ssePath, "/")] // /9da4ht4y/sse → /9da4ht4y
	if sseDir != "" && !strings.HasPrefix(postPath, sseDir) {
		resolvedPostPath = sseDir + postPath // /9da4ht4y + /messages/?session_id=xxx
	}
	postURL := baseURL + resolvedPostPath
	body := initializeRequest("2024-11-05")
	postReq, err := http.NewRequestWithContext(sessCtx, "POST", postURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("User-Agent", config.UserAgent)

	start := time.Now()
	postResp, err := client.Do(postReq)
	if err != nil {
		return nil
	}
	defer postResp.Body.Close()
	elapsed := float64(time.Since(start).Milliseconds())
	postHeaders := relevantHeaders(postResp.Header)

	switch postResp.StatusCode {
	case 200:
		var data map[string]interface{}
		if err := json.NewDecoder(io.LimitReader(postResp.Body, 1<<20)).Decode(&data); err != nil {
			return nil
		}
		score, serverName, serverVer, protocolVer, caps, fingerprint := scoreFingerprintDetailed(data)
		if score < 0.35 {
			return nil
		}
		fingerprint.Score = score
		evidence := models.MCPEvidence{
			URL:              baseURL + ssePath,
			Transport:        models.TransportHTTPSSELegacy,
			ProtocolVersion:  protocolVer,
			ResponseHeaders:  postHeaders,
			JSONRPC:          summarizeJSONRPC("initialize", postResp.StatusCode, postResp.Header.Get("Content-Type"), data),
			Fingerprint:      fingerprint,
			Auth:             models.AuthEvidence{Status: "no-auth", Reasons: []string{"legacy SSE initialize returned a valid MCP JSON-RPC result"}},
			ResponseTimeMs:   elapsed,
			ResolvedPostPath: resolvedPostPath,
		}
		return sseProbeResult(resolvedPostPath, elapsed, score, serverName, serverVer, protocolVer, caps, marshalRaw(data), evidence)

	case 202:
		// 异步响应：从 SSE 流等待 message event
		select {
		case data := <-msgCh:
			score, serverName, serverVer, protocolVer, caps, fingerprint := scoreFingerprintDetailed(data)
			if score < 0.35 {
				return nil
			}
			fingerprint.Score = score
			evidence := models.MCPEvidence{
				URL:              baseURL + ssePath,
				Transport:        models.TransportHTTPSSELegacy,
				ProtocolVersion:  protocolVer,
				ResponseHeaders:  postHeaders,
				JSONRPC:          summarizeJSONRPC("initialize", postResp.StatusCode, postResp.Header.Get("Content-Type"), data),
				Fingerprint:      fingerprint,
				Auth:             models.AuthEvidence{Status: "no-auth", Reasons: []string{"legacy SSE async initialize returned a valid MCP JSON-RPC result"}},
				ResponseTimeMs:   elapsed,
				ResolvedPostPath: resolvedPostPath,
			}
			return sseProbeResult(resolvedPostPath, elapsed, score, serverName, serverVer, protocolVer, caps, marshalRaw(data), evidence)
		case <-sessCtx.Done():
			return nil
		}

	default:
		return nil
	}
}

// sseProbeResult 构建 SSE legacy ProbeResult
func sseProbeResult(postPath string, elapsed, score float64, serverName, serverVer, protocolVer string, caps map[string]interface{}, raw json.RawMessage, evidence models.MCPEvidence) *ProbeResult {
	return &ProbeResult{
		Transport:        models.TransportHTTPSSELegacy,
		FingerprintScore: score,
		ServerName:       serverName,
		ServerVersion:    serverVer,
		ProtocolVersion:  protocolVer,
		Capabilities:     caps,
		RawResponse:      raw,
		NoAuth:           true,
		MessagePath:      postPath,
		ResponseTimeMs:   elapsed,
		Evidence:         evidence,
	}
}

// scoreFingerprint 三层指纹打分
// 实际最大分：protocolVersion(0.2) + capKey(0.3) + serverName(0.1) = 0.6
// 注：L3（ping/notifications）在 ProbeMCP 外层补充，满分 1.0
// 阈值策略（宁可误报，不要漏）：
//   - 0.35 正常门槛
//   - 例外1：protocolVersion + serverInfo.name 同时存在 → 两个规范 REQUIRED 字段，强制 0.35
//   - 例外2：响应是 JSON-RPC 错误格式（有 "error" 无 "result"）→ 服务存在的证据，给 0.2 基础分
func scoreFingerprintDetailed(data map[string]interface{}) (float64, string, string, string, map[string]interface{}, models.FingerprintEvidence) {
	evidence := models.FingerprintEvidence{}
	result, ok := data["result"].(map[string]interface{})
	if !ok {
		// 没有 result 字段，但如果是 JSON-RPC error 响应，说明服务存在
		// 给 0.2 分（低于阈值，由调用方决定是否兜底）
		if _, hasErr := data["error"]; hasErr {
			if v, _ := data["jsonrpc"].(string); v == "2.0" {
				evidence.Score = 0.2
				evidence.Signals = append(evidence.Signals, "jsonrpc_error")
				return 0.2, "", "", "", nil, evidence
			}
		}
		return 0, "", "", "", nil, evidence
	}

	score := 0.0
	evidence.Signals = append(evidence.Signals, "jsonrpc_result")

	// protocolVersion 存在 → +0.2
	protocolVer, _ := result["protocolVersion"].(string)
	if protocolVer != "" {
		score += 0.2
		evidence.Signals = append(evidence.Signals, "protocol_version")
	}

	// capabilities 含 MCP 特有 key → +0.3（出现 LSP key 直接返回 0）
	var caps map[string]interface{}
	if c, ok := result["capabilities"].(map[string]interface{}); ok {
		caps = c
		for k := range c {
			if lspCapKeys[k] {
				evidence.Signals = append(evidence.Signals, "lsp_capability_rejected")
				return 0, "", "", "", nil, evidence // 确定是 LSP
			}
			if mcpCapKeys[k] {
				score += 0.3
				evidence.Signals = append(evidence.Signals, "capabilities."+k)
				break
			}
		}
	}

	// serverInfo 存在 → 额外加分（规范 REQUIRED 字段）
	var serverName, serverVer string
	if si, ok := result["serverInfo"].(map[string]interface{}); ok {
		serverName, _ = si["name"].(string)
		serverVer, _ = si["version"].(string)
		if serverName != "" {
			score += 0.1
			evidence.Signals = append(evidence.Signals, "server_info.name")
		}
	}

	// protocolVersion + serverInfo.name 同时存在 → 两个 MCP 规范 REQUIRED 字段齐全，
	// 即便 capabilities 为空（合法）也应确认为 MCP，强制达到阈值。
	if protocolVer != "" && serverName != "" && score < 0.35 {
		score = 0.35
		evidence.Signals = append(evidence.Signals, "required_fields_threshold")
	}

	evidence.Score = score
	return score, serverName, serverVer, protocolVer, caps, evidence
}

// InitializeRequest returns a pre-built MCP initialize request body for the given protocol version.
// Exported for use by other packages (e.g., analysis).
func InitializeRequest(version string) []byte {
	return initializeRequest(version)
}

func marshalRaw(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// relevantHeaders keeps only headers useful for reproducing MCP detection.
func relevantHeaders(headers http.Header) map[string]string {
	keys := []string{
		"Content-Type",
		"Server",
		"WWW-Authenticate",
		"MCP-Protocol-Version",
		"MCP-Session-Id",
		"Mcp-Protocol-Version",
		"Mcp-Session-Id",
		"Location",
	}
	out := make(map[string]string)
	for _, key := range keys {
		if value := headers.Get(key); value != "" {
			out[http.CanonicalHeaderKey(key)] = value
		}
	}
	return out
}

func summarizeJSONRPC(method string, statusCode int, contentType string, data map[string]interface{}) models.JSONRPCSummary {
	summary := models.JSONRPCSummary{
		RequestMethod: method,
		StatusCode:    statusCode,
		ContentType:   contentType,
	}
	if data == nil {
		return summary
	}
	if result, ok := data["result"].(map[string]interface{}); ok {
		summary.HasResult = true
		for key := range result {
			summary.ResultKeys = append(summary.ResultKeys, key)
		}
		sort.Strings(summary.ResultKeys)
	}
	if errVal, ok := data["error"]; ok && errVal != nil {
		summary.HasError = true
		if errMap, ok := errVal.(map[string]interface{}); ok {
			if code, exists := errMap["code"]; exists {
				summary.ErrorCode = fmt.Sprint(code)
			}
			if msg, _ := errMap["message"].(string); msg != "" {
				summary.ErrorMessage = msg
			}
		}
	}
	return summary
}

// isMCPAuthRequiredWithEvidence explains whether a 4xx response is an MCP auth challenge.
func isMCPAuthRequiredWithEvidence(resp *http.Response, endpoint string, authPaths map[string]bool) (bool, models.AuthEvidence) {
	evidence := models.AuthEvidence{Status: "unknown"}
	switch resp.StatusCode {
	case 406:
		evidence.Reasons = append(evidence.Reasons, "HTTP 406 content negotiation failure")
		return false, evidence
	case 404:
		evidence.Reasons = append(evidence.Reasons, "HTTP 404 endpoint not found")
		return false, evidence
	case 405:
		// Method Not Allowed：路径存在但不接受 POST，典型 SSE legacy 端点（只接受 GET）
		// 不当作 auth-required，让调用方继续尝试 SSE legacy 探测
		evidence.Reasons = append(evidence.Reasons, "HTTP 405 method not allowed; may be SSE-only endpoint")
		return false, evidence
	}

	score := 0
	code := resp.StatusCode
	if resp.Header.Get("MCP-Protocol-Version") != "" || resp.Header.Get("MCP-Session-Id") != "" {
		score += 2
		evidence.Reasons = append(evidence.Reasons, "MCP response header present")
	}
	if code == 401 || code == 403 || (code == 400 && resp.Header.Get("WWW-Authenticate") != "") {
		score++
		evidence.Reasons = append(evidence.Reasons, fmt.Sprintf("HTTP %d auth challenge", code))
	}
	if authPaths[endpoint] {
		score++
		evidence.Reasons = append(evidence.Reasons, "known MCP endpoint path")
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err == nil && len(body) > 0 {
		bodyStr := string(body)
		bodyLower := strings.ToLower(bodyStr)
		if code == 400 && strings.Contains(bodyLower, "session") {
			evidence.Reasons = append(evidence.Reasons, "session error is not treated as auth-required")
			return false, evidence
		}
		if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
			score++
			evidence.Reasons = append(evidence.Reasons, "JSON response body")
		}
		if strings.Contains(bodyStr, `"jsonrpc"`) {
			score += 2
			evidence.Reasons = append(evidence.Reasons, "JSON-RPC response body")
		}
		if strings.Contains(bodyStr, `"error"`) {
			score++
			evidence.Reasons = append(evidence.Reasons, "JSON-RPC error response")
		}
	}

	if score >= 2 {
		evidence.Status = "auth-required"
		return true, evidence
	}
	evidence.Status = "not-auth-required"
	evidence.Reasons = append(evidence.Reasons, fmt.Sprintf("auth score %d below threshold", score))
	return false, evidence
}
