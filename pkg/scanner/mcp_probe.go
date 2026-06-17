package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

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
	Endpoint        string
	Transport       models.Transport
	FingerprintScore float64
	SessionID       string
	ProtocolVersion string
	ServerName      string
	ServerVersion   string
	Capabilities    map[string]interface{}
	RawResponse     json.RawMessage
	NoAuth          bool
	ResponseTimeMs  float64
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

		if r := tryStreamableHTTP(ctx, client, url); r != nil {
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
func tryStreamableHTTP(ctx context.Context, client *http.Client, url string) *ProbeResult {
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
		return nil
	}

	ct := resp.Header.Get("Content-Type")
	var data map[string]interface{}

	// 规范允许两种响应形式，都要处理
	if strings.Contains(ct, "text/event-stream") {
		data = parseFirstSSEMessage(io.LimitReader(resp.Body, 2<<20)) // 2MB 上限防止恶意服务器无限流
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
	postPath := parseEndpointEvent(resp.Body)
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

// parseFirstSSEMessage 从 SSE 流中解析第一个 message event 的 JSON
func parseFirstSSEMessage(r io.Reader) map[string]interface{} {
	scanner := bufio.NewScanner(r)
	var eventType, dataLine string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		} else if line == "" && dataLine != "" {
			// 空行 = event 结束
			if eventType == "" || eventType == "message" {
				var data map[string]interface{}
				if err := json.Unmarshal([]byte(dataLine), &data); err == nil {
					return data
				}
			}
			// 重置
			eventType = ""
			dataLine = ""
		}
	}
	return nil
}

// parseEndpointEvent 从旧版 SSE 中读取 endpoint event 的 data
func parseEndpointEvent(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	var eventType, dataLine string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		} else if line == "" {
			if eventType == "endpoint" && dataLine != "" {
				return dataLine
			}
			eventType = ""
			dataLine = ""
		}
	}
	return ""
}

func marshalRaw(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}


