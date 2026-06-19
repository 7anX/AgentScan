package netproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseProxySchemes(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:8080",
		"https://127.0.0.1:8443",
		"socks4://127.0.0.1:1080",
		"socks5://user:pass@127.0.0.1:1080",
	} {
		if _, err := Parse(raw); err != nil {
			t.Fatalf("Parse(%q) error = %v", raw, err)
		}
	}

	for _, raw := range []string{
		"ftp://127.0.0.1:21",
		"http://127.0.0.1",
		"socks5://127.0.0.1:99999",
	} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("Parse(%q) expected error", raw)
		}
	}
}

func TestDialContextHTTPConnectProxy(t *testing.T) {
	defer Configure("") //nolint:errcheck

	target := "example.com:443"
	proxyAddr, gotTarget := startHTTPConnectProxy(t)
	if err := Configure("http://" + proxyAddr); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}

	conn, err := DialContext(context.Background(), "tcp", target, time.Second)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	conn.Close()

	select {
	case got := <-gotTarget:
		if got != target {
			t.Fatalf("CONNECT target = %q, want %q", got, target)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not receive CONNECT")
	}
}

func TestDialContextSOCKS5Proxy(t *testing.T) {
	defer Configure("") //nolint:errcheck

	target := "example.com:443"
	proxyAddr, gotTarget := startSOCKS5Proxy(t)
	if err := Configure("socks5://" + proxyAddr); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}

	conn, err := DialContext(context.Background(), "tcp", target, time.Second)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	conn.Close()

	select {
	case got := <-gotTarget:
		if got != target {
			t.Fatalf("SOCKS5 target = %q, want %q", got, target)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not receive SOCKS5 connect")
	}
}

func startHTTPConnectProxy(t *testing.T) (string, <-chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	targetCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			targetCh <- fields[1]
		}
		for {
			line, err = reader.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}()
	return ln.Addr().String(), targetCh
}

func startSOCKS5Proxy(t *testing.T) (string, <-chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	targetCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		head := make([]byte, 2)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		methods := make([]byte, int(head[1]))
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		req := make([]byte, 4)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		host := ""
		switch req[3] {
		case 0x03:
			var l [1]byte
			if _, err := io.ReadFull(conn, l[:]); err != nil {
				return
			}
			buf := make([]byte, int(l[0]))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			host = string(buf)
		case 0x01:
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			host = net.IP(buf).String()
		default:
			return
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBuf); err != nil {
			return
		}
		port := int(portBuf[0])<<8 | int(portBuf[1])
		targetCh <- net.JoinHostPort(host, strconv.Itoa(port))
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()
	return ln.Addr().String(), targetCh
}
