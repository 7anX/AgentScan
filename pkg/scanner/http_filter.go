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

// FilterHTTP 对开放端口做并发 HTTP 筛选，返回候选列表。
// 全部纳入（高召回率），命中 MCP 特征的标记高优先级。
// dict 为字典集合；传 nil 时使用 config.DefaultDictSet()。
func FilterHTTP(ctx context.Context, ports []PortResult, timeoutMs int, concurrency int, dict *config.DictSet) []HTTPCandidate {
	if dict == nil {
		dict = config.DefaultDictSet()
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	if concurrency <= 0 {
		concurrency = 100
	}
	sem := make(chan struct{}, concurrency)
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
				if dict.HTTPSPorts[p.Port] {
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
			baseURL := fmt.Sprintf("%s://%s:%d", proto, hostForURL(host), p.Port)

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
				req.Header.Set("User-Agent", config.UserAgent)
				if resp, err2 := filterClient.Do(req); err2 == nil {
					connOK = true
					server = strings.ToLower(resp.Header.Get("Server"))
					ct = strings.ToLower(resp.Header.Get("Content-Type"))
					resp.Body.Close()

					for _, hint := range dict.MCPServerHints {
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

			// 若连接失败，尝试备用协议：
			// 1. 用户显式指定了 proto 但打错了 → 试另一个
			// 2. proto 未指定（从端口推断为 http）但 HTTP 失败 → 补试 HTTPS
			//    覆盖场景：8000/8080/3000 等非标准端口跑了 HTTPS
			if !connOK {
				var altProto string
				if p.Proto != "" {
					// 用户指定了协议但失败，试另一个
					if proto == "http" {
						altProto = "https"
					} else {
						altProto = "http"
					}
				} else if proto == "http" {
					// 推断为 http 但失败，补试 https
					altProto = "https"
				}

				if altProto != "" {
					altBaseURL := fmt.Sprintf("%s://%s:%d", altProto, hostForURL(host), p.Port)
					altReq, err2 := http.NewRequestWithContext(ctx, "GET", altBaseURL+"/", nil)
					if err2 == nil {
						altReq.Header.Set("User-Agent", config.UserAgent)
						if resp, err3 := filterClient.Do(altReq); err3 == nil {
							baseURL = altBaseURL
							server = strings.ToLower(resp.Header.Get("Server"))
							ct = strings.ToLower(resp.Header.Get("Content-Type"))
							resp.Body.Close()

							for _, hint := range dict.MCPServerHints {
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

func hostForURL(host string) string {
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
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
