package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/agentscan/agentscan/pkg/netproxy"
	"github.com/agentscan/agentscan/pkg/target"
	"golang.org/x/sync/semaphore"
)

// PortResult 端口探测结果
type PortResult struct {
	IP       string
	Port     int
	Hostname string // 传递自 Target，用于后续 SNI
	URLPath  string // 用户指定的路径（如 /mcp）
	Proto    string // 用户指定的协议（"http"/"https"），为空时由 FilterHTTP 按端口推断
	Open     bool
}

// ScanPorts 并发 TCP 探测，返回开放端口列表
func ScanPorts(ctx context.Context, targets []target.Target, concurrency int, timeoutMs int, verbose bool, delayMs int) []PortResult {
	sem := semaphore.NewWeighted(int64(concurrency))
	timeout := time.Duration(timeoutMs) * time.Millisecond

	total := len(targets)
	fmt.Fprintf(os.Stderr, "[1/3] port scan    %d probes\n", total)

	var mu sync.Mutex
	var results []PortResult

	var wg sync.WaitGroup
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		if err := sem.Acquire(ctx, 1); err != nil {
			break
		}
		scanDelay(delayMs)
		wg.Add(1)
		go func(t target.Target) {
			defer wg.Done()
			defer sem.Release(1)

			open := tcpConnect(ctx, t.IP, t.Port, timeout)
			if open {
				host := t.IP
				if t.Hostname != "" {
					host = t.Hostname
				}
				mu.Lock()
				results = append(results, PortResult{IP: t.IP, Port: t.Port, Hostname: t.Hostname, URLPath: t.URLPath, Proto: t.Proto, Open: true})
				mu.Unlock()
				if verbose {
					fmt.Fprintf(os.Stderr, "      open  %s:%d\n", host, t.Port)
				}
			}
		}(t)
	}
	wg.Wait()

	fmt.Fprintf(os.Stderr, "      %d/%d open\n\n", len(results), total)
	return results
}

func tcpConnect(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := netproxy.DialContext(ctx, "tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
