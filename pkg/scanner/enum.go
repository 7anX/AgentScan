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


