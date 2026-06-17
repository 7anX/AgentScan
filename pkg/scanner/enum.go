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

// ── Streamable HTTP 枚举（2025-03-26+ transport） ─────────────────────────────

// EnumerateTools 枚举服务器工具列表（只读，不调用 tools/call）
// hostname 用于 HTTPS SNI，为空时从 baseURL 推断
// messagePath 仅 SSE legacy transport 有效：GET /sse 返回的 POST endpoint 路径
// （如 /mcp/v1/basic/message/?session_id=xxx）；非空时优先于 endpoint
func EnumerateTools(ctx context.Context, baseURL, endpoint, messagePath, sessionID, hostname string, timeoutMs int) []models.MCPTool {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := buildHTTPClient(hostname, timeout)

	postURL := resolvePostURL(baseURL, endpoint, messagePath)

	// #5: 发送 notifications/initialized，完成 MCP 握手
	// 严格实现要求在 initialize 之后、任何请求之前收到此通知
	sendNotification(ctx, client, postURL, sessionID)

	data := mcpRequest(ctx, client, postURL, sessionID, 2, "tools/list", map[string]interface{}{})
	if data == nil {
		return nil
	}
	return extractTools(data)
}

// EnumerateResources 枚举服务器资源列表（只读采样，不调用 resources/read）
func EnumerateResources(ctx context.Context, baseURL, endpoint, messagePath, sessionID, hostname string, timeoutMs int) []models.MCPResource {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := buildHTTPClient(hostname, timeout)

	postURL := resolvePostURL(baseURL, endpoint, messagePath)
	data := mcpRequest(ctx, client, postURL, sessionID, 3, "resources/list", map[string]interface{}{})
	if data == nil {
		return nil
	}
	return extractResources(data)
}

// EnumerateResourceTemplates 枚举服务器资源模板列表（resources/templates/list）
func EnumerateResourceTemplates(ctx context.Context, baseURL, endpoint, messagePath, sessionID, hostname string, timeoutMs int) []models.MCPResourceTemplate {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := buildHTTPClient(hostname, timeout)

	postURL := resolvePostURL(baseURL, endpoint, messagePath)
	data := mcpRequest(ctx, client, postURL, sessionID, 5, "resources/templates/list", map[string]interface{}{})
	if data == nil {
		return nil
	}
	return extractResourceTemplates(data)
}

// EnumeratePrompts 枚举服务器提示词列表
func EnumeratePrompts(ctx context.Context, baseURL, endpoint, messagePath, sessionID, hostname string, timeoutMs int) []models.MCPPrompt {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := buildHTTPClient(hostname, timeout)

	postURL := resolvePostURL(baseURL, endpoint, messagePath)
	data := mcpRequest(ctx, client, postURL, sessionID, 4, "prompts/list", map[string]interface{}{})
	if data == nil {
		return nil
	}
	return extractPrompts(data)
}

// ── SSE Legacy 枚举（2024-11-05 transport） ───────────────────────────────────

// EnumerateAllSSELegacy 在单个 SSE session 内依次枚举 tools、resources、resource templates、prompts，
// 避免为每类数据单独握手。返回四者切片（任一为 nil 表示服务端不支持或返回空）。
func EnumerateAllSSELegacy(ctx context.Context, baseURL, ssePath, hostname string, timeoutMs int) ([]models.MCPTool, []models.MCPResource, []models.MCPResourceTemplate, []models.MCPPrompt) {
	sess := newSSESession(ctx, baseURL, ssePath, hostname, timeoutMs)
	if sess == nil {
		return nil, nil, nil, nil
	}
	defer sess.cancel()

	// #5: 完成 MCP 握手
	sendNotification(sess.ctx, sess.client, sess.postURL, "")

	tools := extractTools(sseRequest(sess, 2, "tools/list", map[string]interface{}{}))
	resources := extractResources(sseRequest(sess, 3, "resources/list", map[string]interface{}{}))
	templates := extractResourceTemplates(sseRequest(sess, 5, "resources/templates/list", map[string]interface{}{}))
	prompts := extractPrompts(sseRequest(sess, 4, "prompts/list", map[string]interface{}{}))
	return tools, resources, templates, prompts
}

// ── 内部：SSE session 复用 ────────────────────────────────────────────────────

type sseSession struct {
	ctx     context.Context
	cancel  context.CancelFunc
	client  *http.Client
	postURL string
	msgCh   chan map[string]interface{}
}

// newSSESession 建立 SSE 长连接，返回可复用的 session 对象。
// 调用方负责调用 sess.cancel() 关闭连接。
func newSSESession(ctx context.Context, baseURL, ssePath, hostname string, timeoutMs int) *sseSession {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := buildHTTPClient(hostname, timeout)

	sessCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*5*time.Millisecond)

	sseReq, err := http.NewRequestWithContext(sessCtx, "GET", baseURL+ssePath, nil)
	if err != nil {
		cancel()
		return nil
	}
	sseReq.Header.Set("Accept", "text/event-stream")

	sseResp, err := client.Do(sseReq)
	if err != nil {
		cancel()
		return nil
	}

	if sseResp.StatusCode != 200 {
		sseResp.Body.Close()
		cancel()
		return nil
	}

	postPathCh := make(chan string, 1)
	msgCh := make(chan map[string]interface{}, 16)
	go func() {
		defer sseResp.Body.Close()
		sseutil.ParseEndpointAndListen(sseResp.Body, postPathCh, msgCh)
	}()

	var postPath string
	select {
	case postPath = <-postPathCh:
	case <-sessCtx.Done():
		cancel()
		return nil
	}

	if postPath == "" || !strings.HasPrefix(postPath, "/") ||
		strings.Contains(postPath, "..") || strings.Contains(postPath, "://") {
		cancel()
		return nil
	}

	// initialize
	initBody := mustMarshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "agentscan", "version": "1.0.0"},
		},
	})
	postURL := baseURL + postPath
	initReq, err := http.NewRequestWithContext(sessCtx, "POST", postURL, bytes.NewReader(initBody))
	if err != nil {
		cancel()
		return nil
	}
	initReq.Header.Set("Content-Type", "application/json")
	initResp, err := client.Do(initReq)
	if err != nil {
		cancel()
		return nil
	}
	// drain body regardless of status
	io.Copy(io.Discard, io.LimitReader(initResp.Body, 1<<20)) //nolint:errcheck
	initResp.Body.Close()

	if initResp.StatusCode != 200 && initResp.StatusCode != 202 {
		cancel()
		return nil
	}

	// consume any async initialize response from SSE stream (202 case)
	if initResp.StatusCode == 202 {
		select {
		case <-msgCh: // discard initialize result
		case <-sessCtx.Done():
			cancel()
			return nil
		}
	}

	return &sseSession{
		ctx:     sessCtx,
		cancel:  cancel,
		client:  client,
		postURL: postURL,
		msgCh:   msgCh,
	}
}

// sseRequest sends a JSON-RPC request over an existing SSE session and returns the parsed response.
func sseRequest(sess *sseSession, id int, method string, params interface{}) map[string]interface{} {
	body := mustMarshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	})
	req, err := http.NewRequestWithContext(sess.ctx, "POST", sess.postURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := sess.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "text/event-stream") {
			return sseutil.ParseFirstMessage(resp.Body)
		}
		var data map[string]interface{}
		json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data) //nolint:errcheck
		return data
	case 202:
		select {
		case data := <-sess.msgCh:
			return data
		case <-sess.ctx.Done():
			return nil
		}
	default:
		return nil
	}
}

// ── 内部：通用 helpers ────────────────────────────────────────────────────────

// resolvePostURL 计算实际 POST URL（messagePath 优先于 endpoint）
func resolvePostURL(baseURL, endpoint, messagePath string) string {
	if messagePath != "" {
		return baseURL + messagePath
	}
	return baseURL + endpoint
}

// sendNotification 发送 notifications/initialized（fire-and-forget，不等响应）
// MCP 规范要求 client 在 initialize 成功后发此通知才算握手完成。
func sendNotification(ctx context.Context, client *http.Client, postURL, sessionID string) {
	body := mustMarshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]interface{}{},
		// notifications 无 "id" 字段（规范规定）
	})
	req, err := http.NewRequestWithContext(ctx, "POST", postURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	resp.Body.Close()
}

// mcpRequest 发送一个 JSON-RPC 请求到 streamable HTTP endpoint，返回解析后的响应。
func mcpRequest(ctx context.Context, client *http.Client, postURL, sessionID string, id int, method string, params interface{}) map[string]interface{} {
	body := mustMarshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", postURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		return sseutil.ParseFirstMessage(resp.Body)
	}
	var data map[string]interface{}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data) //nolint:errcheck
	return data
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// ── 提取器 ────────────────────────────────────────────────────────────────────

func extractTools(data map[string]interface{}) []models.MCPTool {
	if data == nil {
		return nil
	}
	result, ok := data["result"].(map[string]interface{})
	if !ok {
		return nil
	}
	toolsRaw, ok := result["tools"].([]interface{})
	if !ok {
		return nil
	}
	var tools []models.MCPTool
	for _, t := range toolsRaw {
		toolMap, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		tool := models.MCPTool{}
		tool.Name, _ = toolMap["name"].(string)
		tool.Description, _ = toolMap["description"].(string)
		if schema, ok := toolMap["inputSchema"].(map[string]interface{}); ok {
			tool.InputSchema = schema
		}
		if tool.Name != "" {
			tools = append(tools, tool)
		}
	}
	return tools
}

func extractResources(data map[string]interface{}) []models.MCPResource {
	if data == nil {
		return nil
	}
	result, ok := data["result"].(map[string]interface{})
	if !ok {
		return nil
	}
	raw, ok := result["resources"].([]interface{})
	if !ok {
		return nil
	}
	var resources []models.MCPResource
	for _, r := range raw {
		m, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		res := models.MCPResource{}
		res.URI, _ = m["uri"].(string)
		res.Name, _ = m["name"].(string)
		res.Description, _ = m["description"].(string)
		res.MIMEType, _ = m["mimeType"].(string)
		if res.URI != "" {
			resources = append(resources, res)
		}
	}
	return resources
}

func extractPrompts(data map[string]interface{}) []models.MCPPrompt {
	if data == nil {
		return nil
	}
	result, ok := data["result"].(map[string]interface{})
	if !ok {
		return nil
	}
	raw, ok := result["prompts"].([]interface{})
	if !ok {
		return nil
	}
	var prompts []models.MCPPrompt
	for _, p := range raw {
		m, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		prompt := models.MCPPrompt{}
		prompt.Name, _ = m["name"].(string)
		prompt.Description, _ = m["description"].(string)
		if prompt.Name != "" {
			prompts = append(prompts, prompt)
		}
	}
	return prompts
}

func extractResourceTemplates(data map[string]interface{}) []models.MCPResourceTemplate {
	if data == nil {
		return nil
	}
	result, ok := data["result"].(map[string]interface{})
	if !ok {
		return nil
	}
	raw, ok := result["resourceTemplates"].([]interface{})
	if !ok {
		return nil
	}
	var templates []models.MCPResourceTemplate
	for _, t := range raw {
		m, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		tmpl := models.MCPResourceTemplate{}
		tmpl.URITemplate, _ = m["uriTemplate"].(string)
		tmpl.Name, _ = m["name"].(string)
		tmpl.Description, _ = m["description"].(string)
		tmpl.MIMEType, _ = m["mimeType"].(string)
		if tmpl.URITemplate != "" {
			templates = append(templates, tmpl)
		}
	}
	return templates
}
