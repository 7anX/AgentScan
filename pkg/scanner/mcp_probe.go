package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
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
				"name":    "agentscan",
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
	return ProbeMCPWithHostname(ctx, baseURL, "", "", timeoutMs)
}

// ProbeMCPWithHostname 支持指定 hostname（SNI）和 urlPath（优先端点）的 MCP 探测
func ProbeMCPWithHostname(ctx context.Context, baseURL, hostname, urlPath string, timeoutMs int) *ProbeResult {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := buildHTTPClient(hostname, timeout)

	// 如果用户指定了具体路径（如 /mcp, /custom-mcp），优先尝试该路径
	endpoints := config.MCPEndpoints
	if urlPath != "" && urlPath != "/" {
		deduped := []string{urlPath}
		for _, ep := range config.MCPEndpoints {
			if ep != urlPath {
				deduped = append(deduped, ep)
			}
		}
		endpoints = deduped
	}

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

			r := tryStreamableHTTP(probeCtx, client, url, ep)
			if r != nil {
				r.Endpoint = ep
				resultCh <- result{r, priority}
				return
			}

			if ep == "/sse" {
				if r := tryHTTPSSELegacy(probeCtx, client, baseURL, timeout); r != nil {
					r.Endpoint = "/sse"
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

	for res := range resultCh {
		if !res.r.AuthRequired {
			if res.priority < bestNoAuthPriority {
				bestNoAuth = res.r
				bestNoAuthPriority = res.priority
			}
		} else {
			if res.priority < bestAuthPriority {
				bestAuthRequired = res.r
				bestAuthPriority = res.priority
			}
		}
	}

	if bestNoAuth != nil {
		return bestNoAuth
	}
	return bestAuthRequired
}

// tryStreamableHTTP POST /mcp 尝试 Streamable HTTP（2025-03-26+）
// endpoint 参数用于辅助 auth-required 判断（/mcp、/sse 等 MCP 特征路径名）
func tryStreamableHTTP(ctx context.Context, client *http.Client, url, endpoint string) *ProbeResult {
	// 单个端点探测最多等 3 秒，避免 20 个端点串行时总超时爆炸
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	body := initializeRequest("2025-06-18")

	req, err := http.NewRequestWithContext(probeCtx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	// 规范 REQUIRED：必须同时列出两种 Accept
	req.Header.Set("Accept", "application/json, text/event-stream")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	elapsed := float64(time.Since(start).Milliseconds())

	if resp.StatusCode != 200 {
		// 检测是否为需要认证的 MCP 服务器（三个条件同时满足才报告，避免误报）：
		// 1. 状态码明确表示认证失败（401/403），或 400 且带 WWW-Authenticate
		// 2. 响应体包含 "jsonrpc" 字段（JSON-RPC 协议特征）
		// 3. 响应体包含 "error" 字段，或响应头有 MCP-Session-Id / MCP-Protocol-Version
		if isMCPAuthRequired(resp, endpoint) {
			return &ProbeResult{
				Transport:        models.TransportStreamableHTTP,
				FingerprintScore: 0.5, // 固定中间分：确认是 MCP，但无法完整指纹
				NoAuth:           false,
				AuthRequired:     true,
				ResponseTimeMs:   elapsed,
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
			return nil
		}
	}

	if data == nil {
		return nil
	}

	score, serverName, serverVer, protocolVer, caps := scoreFingerprint(data)
	if score < 0.35 {
		return nil // 太低，跳过
	}

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
	}
}

// tryHTTPSSELegacy 旧版 HTTP+SSE（2024-11-05）
// 正确实现：保持 GET /sse 连接不关闭，并行 POST，从 SSE 流读响应。
// 这是 SSE legacy 的核心协议要求：session 与连接绑定，断开连接即 session 失效。
func tryHTTPSSELegacy(ctx context.Context, client *http.Client, baseURL string, timeout time.Duration) *ProbeResult {
	// 整个 SSE 会话使用独立超时，不依赖外层 ctx
	sessCtx, sessCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer sessCancel()

	// Step 1: 建立 SSE 连接并启动监听 goroutine
	sseReq, err := http.NewRequestWithContext(sessCtx, "GET", baseURL+"/sse", nil)
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
	postURL := baseURL + postPath
	body := initializeRequest("2024-11-05")
	postReq, err := http.NewRequestWithContext(sessCtx, "POST", postURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	postReq.Header.Set("Content-Type", "application/json")

	start := time.Now()
	postResp, err := client.Do(postReq)
	if err != nil {
		return nil
	}
	defer postResp.Body.Close()
	elapsed := float64(time.Since(start).Milliseconds())

	switch postResp.StatusCode {
	case 200:
		var data map[string]interface{}
		if err := json.NewDecoder(io.LimitReader(postResp.Body, 1<<20)).Decode(&data); err != nil {
			return sseProbeResult(postPath, elapsed, 0.4, "", "", "", nil, nil)
		}
		score, serverName, serverVer, protocolVer, caps := scoreFingerprint(data)
		if score < 0.35 {
			score = 0.4
		}
		return sseProbeResult(postPath, elapsed, score, serverName, serverVer, protocolVer, caps, marshalRaw(data))

	case 202:
		// 异步响应：从 SSE 流等待 message event
		select {
		case data := <-msgCh:
			score, serverName, serverVer, protocolVer, caps := scoreFingerprint(data)
			if score < 0.35 {
				score = 0.4
			}
			return sseProbeResult(postPath, elapsed, score, serverName, serverVer, protocolVer, caps, marshalRaw(data))
		case <-sessCtx.Done():
			return sseProbeResult(postPath, elapsed, 0.4, "", "", "", nil, nil)
		}

	default:
		return nil
	}
}

// sseProbeResult 构建 SSE legacy ProbeResult
func sseProbeResult(postPath string, elapsed, score float64, serverName, serverVer, protocolVer string, caps map[string]interface{}, raw json.RawMessage) *ProbeResult {
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
	}
}

// scoreFingerprint 三层指纹打分
// 实际最大分：protocolVersion(0.2) + capKey(0.3) + serverName(0.1) = 0.6
// 注：L3（ping/notifications）在 ProbeMCP 外层补充，满分 1.0
// 当前阈值 0.35 可匹配 protocolVersion+capKey 的服务器（得分0.5）
func scoreFingerprint(data map[string]interface{}) (float64, string, string, string, map[string]interface{}) {
	result, ok := data["result"].(map[string]interface{})
	if !ok {
		return 0, "", "", "", nil
	}

	score := 0.0

	// protocolVersion 存在 → +0.2
	protocolVer, _ := result["protocolVersion"].(string)
	if protocolVer != "" {
		score += 0.2
	}

	// capabilities 含 MCP 特有 key → +0.3（出现 LSP key 直接返回 0）
	var caps map[string]interface{}
	if c, ok := result["capabilities"].(map[string]interface{}); ok {
		caps = c
		for k := range c {
			if lspCapKeys[k] {
				return 0, "", "", "", nil // 确定是 LSP
			}
			if mcpCapKeys[k] {
				score += 0.3
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
			score += 0.1 // serverInfo 是 MCP 规范 REQUIRED，加分
		}
	}

	return score, serverName, serverVer, protocolVer, caps
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

// isMCPAuthRequired 判断 4xx 响应是否来自需要认证的 MCP 服务器。
// 综合多个信号打分，避免普通 Web 应用误报：
//   - MCP 特有响应头（MCP-Protocol-Version / MCP-Session-Id）：强信号 +2
//   - 状态码 401/403，或 400+WWW-Authenticate：认证拒绝信号 +1
//   - 端点路径是 /mcp 或 /sse 等 MCP 特征路径：路径信号 +1
//   - 响应体 Content-Type 是 application/json：JSON API 信号 +1
//   - 响应体含 "jsonrpc" 字段：JSON-RPC 信号 +2
//   - 响应体含 "error" 字段：错误响应信号 +1
//
// 总分 ≥ 3 才认为是 auth-required MCP（防止单一信号误报）
// 排除的状态码：
//   - 406 Not Acceptable：内容协商失败，不是认证错误
//   - 404 Not Found：资源不存在（SSE legacy 无 session 的 /messages 返回 404，
//                   是正常业务逻辑，不是认证拒绝）
func isMCPAuthRequired(resp *http.Response, endpoint string) bool {
	switch resp.StatusCode {
	case 406:
		// 内容协商失败，调用方应换参数重试
		return false
	case 404:
		// 资源不存在（SSE legacy 无有效 session 时 /messages 返回 404）
		// 不是认证错误，排除
		return false
	}

	score := 0

	// MCP 特有 header（最强信号）
	if resp.Header.Get("MCP-Protocol-Version") != "" || resp.Header.Get("MCP-Session-Id") != "" {
		score += 2
	}

	// 状态码信号
	code := resp.StatusCode
	if code == 401 || code == 403 || (code == 400 && resp.Header.Get("WWW-Authenticate") != "") {
		score += 1
	}

	// 端点路径信号：已知 MCP 特征路径
	if config.MCPAuthPaths[endpoint] {
		score += 1
	}

	// 响应体信号
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err == nil && len(body) > 0 {
		bodyStr := string(body)

		// 400 + body 含 "session" → SSE legacy 的 session 错误（如 "No transport found for sessionId"、
		// "Session not found"），不是认证拒绝，直接排除。
		if code == 400 && strings.Contains(strings.ToLower(bodyStr), "session") {
			return false
		}

		isJSONContentType := strings.Contains(
			strings.ToLower(resp.Header.Get("Content-Type")), "application/json")
		if isJSONContentType {
			score += 1
		}
		if strings.Contains(bodyStr, `"jsonrpc"`) {
			score += 2
		}
		if strings.Contains(bodyStr, `"error"`) {
			score += 1
		}
	}

	return score >= 3
}
