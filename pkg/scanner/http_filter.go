package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/agentscan/agentscan/pkg/config"
)

// HTTPCandidate HTTP 筛选结果
type HTTPCandidate struct {
	IP          string
	Port        int
	Hostname    string // 原始域名（用于 HTTPS SNI）
	URLPath     string // 用户指定路径（如 /mcp），优先于默认端点列表
	BaseURL     string
	ServerHdr   string
	ContentType string
	Priority    int
}

// MCP 相关的 Server 头特征（来自 Bitsight 报告）
// 字典维护见 pkg/config/config.go → MCPServerHints
var mcpServerHints = config.MCPServerHints

// FilterHTTP 对开放端口做并发 HTTP 筛选，返回候选列表。
// 全部纳入（高召回率），命中 MCP 特征的标记高优先级。
func FilterHTTP(ctx context.Context, ports []PortResult, timeoutMs int) []HTTPCandidate {
	timeout := time.Duration(timeoutMs) * time.Millisecond

	// 并发执行
	sem := make(chan struct{}, 100)
	var mu sync.Mutex
	var candidates []HTTPCandidate
	var wg sync.WaitGroup

	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			goto done
		}
		wg.Add(1)
		go func(p PortResult) {
			defer wg.Done()
			defer func() { <-sem }()

			// 协议优先级：用户指定 > 端口推断
			proto := p.Proto
			if proto == "" {
				if config.HTTPSPorts[p.Port] {
					proto = "https"
				} else {
					proto = "http"
				}
			}

			// BaseURL 使用 hostname（如有）确保 HTTPS SNI 正确，否则用 IP
			host := p.IP
			if p.Hostname != "" {
				host = p.Hostname
			}
			baseURL := fmt.Sprintf("%s://%s:%d", proto, host, p.Port)

			// FilterHTTP 只需要判断服务器类型，用短超时（timeout）
			// 不用 timeout*3，避免 scheme 误写时 TLS 握手超时拖慢整体进度
			filterClient := buildHTTPClient(p.Hostname, timeout)

			// 尝试 GET / 获取 Server 头做优先级标记
			// 无论返回什么状态码（404/301/308），端口是开放的就纳入候选
			server, ct := "", ""
			priority := 0

			req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/", nil)
			connOK := false
			if err == nil {
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; agentscan/1.0)")
				if resp, err2 := filterClient.Do(req); err2 == nil {
					connOK = true
					server = strings.ToLower(resp.Header.Get("Server"))
					ct = strings.ToLower(resp.Header.Get("Content-Type"))
					resp.Body.Close()

					for _, hint := range mcpServerHints {
						if strings.Contains(server, hint) {
							priority = 2
							break
						}
					}
					if priority == 0 && (strings.Contains(ct, "text/event-stream") || strings.Contains(ct, "application/json")) {
						priority = 1
					}
				} else {
					// GET / 失败（TLS 错误 / 超时）→ connOK=false，触发 proto 降级逻辑
				}
			}

			// 若用户指定了 proto 但连接失败（如写错 https/http），自动尝试另一个协议
			if !connOK && p.Proto != "" {
				altProto := "http"
				if proto == "http" {
					altProto = "https"
				}
				altBaseURL := fmt.Sprintf("%s://%s:%d", altProto, host, p.Port)
				altReq, err2 := http.NewRequestWithContext(ctx, "GET", altBaseURL+"/", nil)
				if err2 == nil {
					altReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; agentscan/1.0)")
					if resp, err3 := filterClient.Do(altReq); err3 == nil {
						connOK = true
						baseURL = altBaseURL // 切换到能用的协议
						server = strings.ToLower(resp.Header.Get("Server"))
						ct = strings.ToLower(resp.Header.Get("Content-Type"))
						resp.Body.Close()

						for _, hint := range mcpServerHints {
							if strings.Contains(server, hint) {
								priority = 2
								break
							}
						}
						if priority == 0 && (strings.Contains(ct, "text/event-stream") || strings.Contains(ct, "application/json")) {
							priority = 1
						}
					}
				}
			}
			// GET / 失败（404/重定向/证书错误）→ priority=0，仍然纳入候选

			mu.Lock()
			candidates = append(candidates, HTTPCandidate{
				IP:          p.IP,
				Port:        p.Port,
				Hostname:    p.Hostname,
				URLPath:     p.URLPath,
				BaseURL:     baseURL,
				ServerHdr:   server,
				ContentType: ct,
				Priority:    priority,
			})
			mu.Unlock()
		}(p)
	}
done:
	wg.Wait()
	return candidates
}

// buildHTTPClient 构建支持 SNI 的 HTTP 客户端
// 当 hostname 不为空时，设置 TLS ServerName 确保 SNI 正确
func buildHTTPClient(hostname string, timeout time.Duration) *http.Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // 扫描器接受自签名证书
	}
	if hostname != "" {
		tlsCfg.ServerName = hostname
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 0,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}

	return &http.Client{
		Timeout:   timeout * 3,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
