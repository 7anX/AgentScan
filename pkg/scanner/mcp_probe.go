package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/agentscan/agentscan/internal/sseutil"
	"github.com/agentscan/agentscan/pkg/models"
)

// MCP 端点尝试顺序（Streamable HTTP 优先）
var mcpEndpoints = []string{"/mcp", "/sse", "/", "/messages", "/api/mcp", "/v1/mcp"}

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
	endpoints := mcpEndpoints
	if urlPath != "" && urlPath != "/" {
		// 把用户指定路径放在最前面
		deduped := []string{urlPath}
		for _, ep := range mcpEndpoints {
			if ep != urlPath {
				deduped = append(deduped, ep)
			}
		}
		endpoints = deduped
	}

	for _, endpoint := range endpoints {
		url := baseURL + endpoint

		if r := tryStreamableHTTP(ctx, client, url, endpoint); r != nil {
			r.Endpoint = endpoint
			return r
		}

		if endpoint == "/sse" {
			if r := tryHTTPSSELegacy(ctx, client, baseURL, timeout); r != nil {
				r.Endpoint = "/sse"
				return r
			}
		}
	}
	return nil
}

// tryStreamableHTTP POST /mcp 尝试 Streamable HTTP（2025-03-26+）
// endpoint 参数用于辅助 auth-required 判断（/mcp、/sse 等 MCP 特征路径名）
func tryStreamableHTTP(ctx context.Context, client *http.Client, url, endpoint string) *ProbeResult {
	body := initializeRequest("2025-06-18")

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
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
func tryHTTPSSELegacy(ctx context.Context, client *http.Client, baseURL string, timeout time.Duration) *ProbeResult {
	// Step 1: GET /sse，使用短超时子 ctx，确保 SSE 长连接被及时关闭
	sseCtx, sseCancel := context.WithTimeout(ctx, 2*time.Second)
	defer sseCancel()

	req, err := http.NewRequestWithContext(sseCtx, "GET", baseURL+"/sse", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	// 读取 endpoint event 后立即排尽并关闭，防止 FD 泄漏
	postPath := sseutil.ParseEndpointEvent(resp.Body)
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	resp.Body.Close()

	if postPath == "" {
		return nil
	}
	// 验证 postPath 安全性：必须以 / 开头，不含 .. 或 ://
	if !strings.HasPrefix(postPath, "/") || strings.Contains(postPath, "..") || strings.Contains(postPath, "://") {
		return nil
	}

	// Step 2: POST 到 endpoint（session 在 URL Query 里，不在 Header 里）
	postURL := baseURL + postPath
	body := initializeRequest("2024-11-05")

	req2, err := http.NewRequestWithContext(ctx, "POST", postURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req2.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp2, err := client.Do(req2)
	if err != nil {
		return nil
	}
	defer resp2.Body.Close()
	elapsed := float64(time.Since(start).Milliseconds())

	if resp2.StatusCode != 200 {
		return nil
	}

	var data map[string]interface{}
	limitedBody := io.LimitReader(resp2.Body, 1<<20)
	if err := json.NewDecoder(limitedBody).Decode(&data); err != nil {
		return nil
	}

	score, serverName, serverVer, protocolVer, caps := scoreFingerprint(data)
	if score < 0.35 {
		return nil
	}

	return &ProbeResult{
		Transport:        models.TransportHTTPSSELegacy,
		FingerprintScore: score,
		ServerName:       serverName,
		ServerVersion:    serverVer,
		ProtocolVersion:  protocolVer,
		Capabilities:     caps,
		RawResponse:      marshalRaw(data),
		NoAuth:           true,
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
func isMCPAuthRequired(resp *http.Response, endpoint string) bool {
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

	// 端点路径信号：/mcp、/sse、/messages、/api/mcp、/v1/mcp 是 MCP 特征路径
	mcpPaths := map[string]bool{
		"/mcp": true, "/sse": true, "/messages": true,
		"/api/mcp": true, "/v1/mcp": true,
	}
	if mcpPaths[endpoint] {
		score += 1
	}

	// 响应体信号
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err == nil && len(body) > 0 {
		isJSONContentType := strings.Contains(
			strings.ToLower(resp.Header.Get("Content-Type")), "application/json")
		if isJSONContentType {
			score += 1
		}
		bodyStr := string(body)
		if strings.Contains(bodyStr, `"jsonrpc"`) {
			score += 2
		}
		if strings.Contains(bodyStr, `"error"`) {
			score += 1
		}
	}

	return score >= 3
}