package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/agentscan/agentscan/pkg/target"
	"golang.org/x/sync/semaphore"
)

// PortResult 端口探测结果
type PortResult struct {
	IP       string
	Port     int
	Hostname string // 传递自 Target，用于后续 SNI
	URLPath  string // 用户指定的路径（如 /mcp）
	Open     bool
}

// ScanPorts 并发 TCP 探测，返回开放端口列表
func ScanPorts(ctx context.Context, targets []target.Target, concurrency int, timeoutMs int) []PortResult {
	sem := semaphore.NewWeighted(int64(concurrency))
	timeout := time.Duration(timeoutMs) * time.Millisecond

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
		wg.Add(1)
		go func(t target.Target) {
			defer wg.Done()
			defer sem.Release(1)

			open := tcpConnect(t.IP, t.Port, timeout)
			if open {
				mu.Lock()
				results = append(results, PortResult{IP: t.IP, Port: t.Port, Hostname: t.Hostname, URLPath: t.URLPath, Open: true})
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()
	return results
}

func tcpConnect(ip string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

