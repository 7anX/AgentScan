package netproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mu      sync.RWMutex
	current *Config
)

// Config describes the explicit proxy used by scanner traffic.
type Config struct {
	Raw string
	URL *url.URL
}

// Configure sets the process-wide proxy used by AgentScan network clients.
func Configure(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		mu.Lock()
		current = nil
		mu.Unlock()
		return nil
	}

	cfg, err := Parse(raw)
	if err != nil {
		return err
	}

	mu.Lock()
	current = cfg
	mu.Unlock()
	return nil
}

// Parse validates a proxy URL.
func Parse(raw string) (*Config, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https", "socks4", "socks5":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, errors.New("proxy must be in scheme://host:port form")
	}
	if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid proxy port %q", u.Port())
	}
	return &Config{Raw: raw, URL: u}, nil
}

// Current returns the configured proxy string, or "" when disabled.
func Current() string {
	cfg := snapshot()
	if cfg == nil {
		return ""
	}
	return cfg.Raw
}

// HTTPProxy returns a Transport.Proxy function for HTTP/HTTPS proxies.
// SOCKS proxies are handled by DialContext instead.
func HTTPProxy() func(*http.Request) (*url.URL, error) {
	cfg := snapshot()
	if cfg == nil {
		return nil
	}
	if cfg.URL.Scheme != "http" && cfg.URL.Scheme != "https" {
		return nil
	}
	return http.ProxyURL(cfg.URL)
}

// HTTPDialContext returns the dial function appropriate for net/http.Transport.
func HTTPDialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	if proxyUsesHTTPTransportProxy() {
		dialer := &net.Dialer{Timeout: timeout, KeepAlive: 0}
		return dialer.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return DialContext(ctx, network, address, timeout)
	}
}

// DialContext opens a TCP connection to address, optionally through the configured proxy.
func DialContext(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxy dial only supports tcp, got %s", network)
	}
	cfg := snapshot()
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 0}
	if cfg == nil {
		return dialer.DialContext(ctx, network, address)
	}

	conn, err := dialer.DialContext(ctx, "tcp", cfg.URL.Host)
	if err != nil {
		return nil, err
	}
	if deadline, ok := handshakeDeadline(ctx, timeout); ok {
		_ = conn.SetDeadline(deadline)
	}

	if cfg.URL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         cfg.URL.Hostname(),
			InsecureSkipVerify: true, //nolint:gosec // scanning tools commonly use private interception proxies.
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	switch cfg.URL.Scheme {
	case "http", "https":
		err = dialHTTPConnect(conn, cfg.URL, address)
	case "socks5":
		err = dialSOCKS5(conn, cfg.URL, address)
	case "socks4":
		err = dialSOCKS4(conn, cfg.URL, address)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func snapshot() *Config {
	mu.RLock()
	defer mu.RUnlock()
	if current == nil {
		return nil
	}
	u := *current.URL
	return &Config{Raw: current.Raw, URL: &u}
}

func proxyUsesHTTPTransportProxy() bool {
	cfg := snapshot()
	return cfg != nil && (cfg.URL.Scheme == "http" || cfg.URL.Scheme == "https")
}

func handshakeDeadline(ctx context.Context, timeout time.Duration) (time.Time, bool) {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if deadline.IsZero() {
		return time.Time{}, false
	}
	return deadline, true
}

func dialHTTPConnect(conn net.Conn, proxyURL *url.URL, target string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", target, target)
	if auth := proxyAuth(proxyURL); auth != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", auth)
	}
	b.WriteString("\r\n")

	if _, err := io.WriteString(conn, b.String()); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	fields := strings.Fields(status)
	if len(fields) < 2 || fields[1] != "200" {
		return fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(status))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}

func dialSOCKS5(conn net.Conn, proxyURL *url.URL, target string) error {
	user := proxyURL.User.Username()
	pass, hasPass := proxyURL.User.Password()
	methods := []byte{0x00}
	if user != "" || hasPass {
		methods = append(methods, 0x02)
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return errors.New("invalid SOCKS5 response")
	}
	switch resp[1] {
	case 0x00:
	case 0x02:
		if err := socks5UserPassAuth(conn, user, pass); err != nil {
			return err
		}
	case 0xff:
		return errors.New("SOCKS5 proxy rejected authentication methods")
	default:
		return fmt.Errorf("SOCKS5 proxy selected unsupported auth method 0x%02x", resp[1])
	}

	host, port, err := splitHostPort(target)
	if err != nil {
		return err
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("SOCKS5 target host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return errors.New("invalid SOCKS5 connect response")
	}
	if head[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed with status 0x%02x", head[1])
	}
	switch head[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, conn, 4)
	case 0x03:
		var l [1]byte
		if _, err = io.ReadFull(conn, l[:]); err == nil {
			_, err = io.CopyN(io.Discard, conn, int64(l[0]))
		}
	case 0x04:
		_, err = io.CopyN(io.Discard, conn, 16)
	default:
		err = fmt.Errorf("invalid SOCKS5 address type 0x%02x", head[3])
	}
	if err != nil {
		return err
	}
	_, err = io.CopyN(io.Discard, conn, 2)
	return err
}

func socks5UserPassAuth(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("SOCKS5 username/password too long")
	}
	msg := []byte{0x01, byte(len(user))}
	msg = append(msg, []byte(user)...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, []byte(pass)...)
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("SOCKS5 username/password authentication failed")
	}
	return nil
}

func dialSOCKS4(conn net.Conn, proxyURL *url.URL, target string) error {
	host, port, err := splitHostPort(target)
	if err != nil {
		return err
	}
	req := []byte{0x04, 0x01, byte(port >> 8), byte(port)}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		req = append(req, 0x00, 0x00, 0x00, 0x01)
	} else {
		req = append(req, ip...)
	}
	req = append(req, []byte(proxyURL.User.Username())...)
	req = append(req, 0x00)
	if ip == nil {
		req = append(req, []byte(host)...)
		req = append(req, 0x00)
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x5a {
		return fmt.Errorf("SOCKS4 connect failed with status 0x%02x", resp[1])
	}
	return nil
}

func splitHostPort(address string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid target port %q", portStr)
	}
	return host, port, nil
}

func proxyAuth(proxyURL *url.URL) string {
	if proxyURL.User == nil {
		return ""
	}
	user := proxyURL.User.Username()
	pass, _ := proxyURL.User.Password()
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}
