package target

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Target 单个扫描目标
type Target struct {
	IP       string
	Port     int
	Hostname string // 原始域名（用于 HTTPS SNI）
	URLPath  string // 用户指定的路径（如 /mcp），优先于默认端点列表
}

// Parse 解析输入，返回 (ip, port) 对列表
// 支持：单 IP、CIDR、IP range（1.1.1.1-2.2.2.2）、域名、host:port、URL
func Parse(input string, ports []int) ([]Target, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}

	// URL 格式：http(s)://host[:port][/path]
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		host, explicitPort, err := extractHostPort(input)
		if err != nil {
			return nil, fmt.Errorf("invalid URL %s: %w", input, err)
		}
		// 提取 path（如 /mcp），优先于默认端点列表
		urlPath := extractURLPath(input)
		ips, err := resolveHost(host)
		if err != nil {
			return nil, err
		}
		hostname := ""
		if net.ParseIP(host) == nil {
			hostname = host
		}
		ts := buildTargetsWithHostname(ips, ports, explicitPort, hostname)
		if urlPath != "" && urlPath != "/" {
			for i := range ts {
				ts[i].URLPath = urlPath
			}
		}
		return ts, nil
	}

	// IP range 格式：1.1.1.1-2.2.2.2
	if isIPRange(input) {
		return parseIPRange(input, ports)
	}

	// CIDR 格式：192.168.1.0/24（/ 后全数字）
	if strings.Contains(input, "/") {
		parts := strings.SplitN(input, "/", 2)
		if isNumeric(parts[1]) {
			return parseCIDR(input, ports)
		}
		// host/path：忽略路径，只扫主机
		host := parts[0]
		ips, err := resolveHost(host)
		if err != nil {
			return nil, err
		}
		hostname := ""
		if net.ParseIP(host) == nil {
			hostname = host
		}
		return buildTargetsWithHostname(ips, ports, 0, hostname), nil
	}

	// host:port 格式
	if strings.Contains(input, ":") {
		host, portStr, err := net.SplitHostPort(input)
		if err == nil {
			var port int
			fmt.Sscanf(portStr, "%d", &port)
			if port > 0 {
				ips, err := resolveHost(host)
				if err != nil {
					return nil, err
				}
				hostname := ""
				if net.ParseIP(host) == nil {
					hostname = host
				}
				return buildTargetsWithHostname(ips, nil, port, hostname), nil
			}
		}
	}

	// 普通 IP 或域名
	ips, err := resolveHost(input)
	if err != nil {
		return nil, err
	}
	hostname := ""
	if net.ParseIP(input) == nil {
		hostname = input
	}
	return buildTargetsWithHostname(ips, ports, 0, hostname), nil
}

// ParseFile 从文件读取目标（每行一个，支持 # 注释）
func ParseFile(path string, ports []int) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var targets []Target
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ts, err := Parse(line, ports)
		if err != nil {
			continue
		}
		targets = append(targets, ts...)
	}
	return targets, scanner.Err()
}

// buildTargets 从 IP 列表 + 端口列表构建目标，保留 hostname 用于 SNI
func buildTargetsWithHostname(ips []string, ports []int, singlePort int, hostname string) []Target {
	var targets []Target
	if singlePort > 0 {
		for _, ip := range ips {
			targets = append(targets, Target{IP: ip, Port: singlePort, Hostname: hostname})
		}
	} else {
		for _, ip := range ips {
			for _, port := range ports {
				targets = append(targets, Target{IP: ip, Port: port, Hostname: hostname})
			}
		}
	}
	return targets
}

// parseCIDR 解析 CIDR，限制最大 /12
func parseCIDR(cidr string, ports []int) ([]Target, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}

	ones, bits := ipnet.Mask.Size()
	if bits-ones > 20 {
		return nil, fmt.Errorf("CIDR /%d too large (max /12); split into smaller ranges", ones)
	}

	broadcast := make(net.IP, len(ipnet.IP))
	for i := range ipnet.IP {
		broadcast[i] = ipnet.IP[i] | ^ipnet.Mask[i]
	}
	broadcastStr := broadcast.String()

	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP.Mask(ipnet.Mask))

	var targets []Target
	for ; ipnet.Contains(ip); inc(ip) {
		ipStr := ip.String()
		if ipStr == ipnet.IP.String() || ipStr == broadcastStr {
			continue
		}
		for _, port := range ports {
			targets = append(targets, Target{IP: ipStr, Port: port})
		}
	}
	return targets, nil
}

// isIPRange 判断是否为 IP range 格式（1.1.1.1-2.2.2.2 或 1.1.1.1-255）
func isIPRange(s string) bool {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return false
	}
	return net.ParseIP(parts[0]) != nil
}

// parseIPRange 解析 IP range
// 支持两种格式：
//   1.1.1.1-2.2.2.2    完整 IP 范围
//   192.168.1.1-255    末段范围（192.168.1.1 ~ 192.168.1.255）
func parseIPRange(s string, ports []int) ([]Target, error) {
	parts := strings.SplitN(s, "-", 2)
	startIP := net.ParseIP(parts[0]).To4()
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP: %s", parts[0])
	}

	var endIP net.IP
	if net.ParseIP(parts[1]) != nil {
		endIP = net.ParseIP(parts[1]).To4()
	} else if isNumeric(parts[1]) {
		// 末段格式：复制前三段，替换末段
		endIP = make(net.IP, 4)
		copy(endIP, startIP)
		var last int
		fmt.Sscanf(parts[1], "%d", &last)
		if last < 0 || last > 255 {
			return nil, fmt.Errorf("invalid end octet %d in range %s (must be 0-255)", last, s)
		}
		endIP[3] = byte(last)
	}
	if endIP == nil {
		return nil, fmt.Errorf("invalid end of range: %s", parts[1])
	}

	startU := ipv4ToU32(startIP)
	endU := ipv4ToU32(endIP)
	if endU < startU {
		return nil, fmt.Errorf("start IP > end IP in range %s", s)
	}
	if endU-startU > 1<<20 {
		return nil, fmt.Errorf("IP range too large (>1M IPs)")
	}

	var targets []Target
	for cur := startU; cur <= endU; cur++ {
		ipStr := u32ToIPv4(cur).String()
		for _, port := range ports {
			targets = append(targets, Target{IP: ipStr, Port: port})
		}
	}
	return targets, nil
}

func ipv4ToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func u32ToIPv4(n uint32) net.IP {
	return net.IP{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}


func resolveHost(host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	return addrs, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// extractURLPath 从 URL 中提取路径部分（不含 query/fragment）
func extractURLPath(rawURL string) string {
	u := rawURL
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	// 去掉 host:port 部分，保留 /path
	if idx := strings.Index(u, "/"); idx >= 0 {
		return u[idx:]
	}
	return "/"
}

func extractHostPort(rawURL string) (string, int, error) {
	u := rawURL
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	if idx := strings.IndexAny(u, "/?#"); idx >= 0 {
		u = u[:idx]
	}
	if strings.Contains(u, ":") {
		host, portStr, err := net.SplitHostPort(u)
		if err != nil {
			return "", 0, err
		}
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		return host, port, nil
	}
	return u, 0, nil
}
