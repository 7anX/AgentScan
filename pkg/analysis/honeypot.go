// Package analysis provides MCP server behavior analysis.
package analysis

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/agentscan/agentscan/internal/sseutil"
	"github.com/agentscan/agentscan/pkg/models"
)

// DetectHoneypot 蜜罐检测（2个强信号）
// hostname 用于 HTTPS SNI，为空时直接用 IP
func DetectHoneypot(ctx context.Context, server *models.MCPServer, hostname string, timeoutMs int) models.HoneypotResult {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := newTLSClient(hostname, timeout)

	score := 0
	var signals []string

	probeURL := server.URL + server.Endpoint

	// 信号1：发送非法版本
	data, _ := sendInitProbe(ctx, client, probeURL, "9999-99-99")
	if data != nil {
		if _, hasResult := data["result"]; hasResult {
			if _, hasError := data["error"]; !hasError {
				score += 20
				signals = append(signals, "invalid_version_accepted:9999-99-99")
			}
		}
	}

	// 信号2：两次 session ID 对比
	if server.SessionID != "" {
		_, sid2 := sendInitProbe(ctx, client, probeURL, "2025-06-18")
		if sid2 != "" && sid2 == server.SessionID {
			score += 40
			signals = append(signals, fmt.Sprintf("session_id_identical:%.16s", server.SessionID))
		}
	}

	return models.HoneypotResult{
		Suspected: score >= 40,
		Score:     score,
		Signals:   signals,
	}
}

// newTLSClient 构建支持 SNI 的 HTTP 客户端（蜜罐检测专用）
func newTLSClient(hostname string, timeout time.Duration) *http.Client {
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	if hostname != "" {
		tlsCfg.ServerName = hostname
	}
	return &http.Client{
		Timeout: timeout * 3,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 0,
			}).DialContext,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// sendInitProbe 发送 initialize 请求，返回响应数据和 session ID
func sendInitProbe(ctx context.Context, client *http.Client, url, version string) (map[string]interface{}, string) {
	body := buildProbeBody(version)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()

	sid := resp.Header.Get("Mcp-Session-Id")

	ct := resp.Header.Get("Content-Type")
	var data map[string]interface{}
	if strings.Contains(ct, "text/event-stream") {
		// 使用 sseutil 共享实现，消除与 mcp_probe.go 的代码重复
		data = sseutil.ParseFirstMessage(io.LimitReader(resp.Body, 2<<20))
	} else {
		// decode error is non-fatal; nil data handled by caller
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data)
	}
	return data, sid
}
// buildProbeBody 构造 MCP initialize 请求体。
// 逻辑与 scanner.initializeRequest 相同，这里独立实现以避免包循环依赖。
func buildProbeBody(version string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": version,
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "agentscan", "version": "1.0.0"},
		},
	})
	return b
}
