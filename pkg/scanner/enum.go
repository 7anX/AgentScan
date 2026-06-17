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

// EnumerateTools 枚举服务器工具列表（只读，不调用 tools/call）
// hostname 用于 HTTPS SNI，为空时从 baseURL 推断
// messagePath 仅 SSE legacy transport 有效：GET /sse 返回的 POST endpoint 路径
// （如 /mcp/v1/basic/message/?session_id=xxx）；非空时优先于 endpoint
func EnumerateTools(ctx context.Context, baseURL, endpoint, messagePath, sessionID, hostname string, timeoutMs int) []models.MCPTool {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := buildHTTPClient(hostname, timeout) // 使用支持 SNI 的客户端

	// SSE legacy：tools/list 必须 POST 到 session message endpoint，而不是 /sse
	postEndpoint := endpoint
	if messagePath != "" {
		postEndpoint = messagePath
	}
	url := baseURL + postEndpoint
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
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

	// 解析响应（支持 JSON 和 SSE 两种形式）
	var data map[string]interface{}
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		data = sseutil.ParseFirstMessage(resp.Body)
	} else {
		limitedBody := io.LimitReader(resp.Body, 1<<20)
		json.NewDecoder(limitedBody).Decode(&data)
	}

	if data == nil {
		return nil
	}

	return extractTools(data)
}

// EnumerateToolsSSELegacy 专用于 SSE legacy transport 的工具枚举。
// 重建 SSE 会话（GET /sse），在会话有效期内 POST tools/list，从流中读响应。
// 这是 SSE legacy 协议的正确做法：session 与 GET /sse 连接绑定。
func EnumerateToolsSSELegacy(ctx context.Context, baseURL, hostname string, timeoutMs int) []models.MCPTool {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := buildHTTPClient(hostname, timeout)

	// 独立超时，不占用外层 ctx
	sessCtx, sessCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer sessCancel()

	// Step 1: 建立 SSE 连接
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

	// 启动监听
	postPathCh := make(chan string, 1)
	msgCh := make(chan map[string]interface{}, 8)
	go sseutil.ParseEndpointAndListen(sseResp.Body, postPathCh, msgCh)

	// Step 2: 等待 endpoint event
	var postPath string
	select {
	case postPath = <-postPathCh:
	case <-sessCtx.Done():
		return nil
	}

	if postPath == "" || !strings.HasPrefix(postPath, "/") ||
		strings.Contains(postPath, "..") || strings.Contains(postPath, "://") {
		return nil
	}

	// Step 3: POST tools/list
	toolsBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	})

	postURL := baseURL + postPath
	postReq, err := http.NewRequestWithContext(sessCtx, "POST", postURL, bytes.NewReader(toolsBody))
	if err != nil {
		return nil
	}
	postReq.Header.Set("Content-Type", "application/json")

	postResp, err := client.Do(postReq)
	if err != nil {
		return nil
	}
	defer postResp.Body.Close()

	switch postResp.StatusCode {
	case 200:
		// 同步响应
		var data map[string]interface{}
		ct := postResp.Header.Get("Content-Type")
		if strings.Contains(ct, "text/event-stream") {
			data = sseutil.ParseFirstMessage(postResp.Body)
		} else {
			json.NewDecoder(io.LimitReader(postResp.Body, 1<<20)).Decode(&data)
		}
		return extractTools(data)

	case 202:
		// 异步响应：从 SSE 流读
		select {
		case data := <-msgCh:
			return extractTools(data)
		case <-sessCtx.Done():
			return nil
		}

	default:
		return nil
	}
}

func extractTools(data map[string]interface{}) []models.MCPTool {
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
