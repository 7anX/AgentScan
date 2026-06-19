package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentscan/agentscan/pkg/config"
	"github.com/agentscan/agentscan/pkg/netproxy"
)

func TestHostForURLBracketsIPv6(t *testing.T) {
	if got := hostForURL("2001:db8::1"); got != "[2001:db8::1]" {
		t.Fatalf("hostForURL IPv6 = %q, want [2001:db8::1]", got)
	}
	if got := hostForURL("example.com"); got != "example.com" {
		t.Fatalf("hostForURL hostname = %q, want example.com", got)
	}
	if got := hostForURL("192.0.2.10"); got != "192.0.2.10" {
		t.Fatalf("hostForURL IPv4 = %q, want 192.0.2.10", got)
	}
}

// startTestServer spins up an httptest.Server that responds with the given
// Server header. Returns the server, its IP, and its port.
func startTestServer(t *testing.T, serverHdr string) (*httptest.Server, string, int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serverHdr != "" {
			w.Header().Set("Server", serverHdr)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	return srv, host, port
}

// TestFilterHTTP_MCPServerHints verifies that a response with a Server header
// matching MCPServerHints receives priority=2.
func TestFilterHTTP_MCPServerHints(t *testing.T) {
	_, ip, port := startTestServer(t, "uvicorn/0.30.0") // "uvicorn" is in default hints

	dict := config.DefaultDictSet()
	ports := []PortResult{{IP: ip, Port: port, Open: true}}
	candidates := FilterHTTP(context.Background(), ports, 3000, 10, dict)

	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Priority != 2 {
		t.Errorf("priority: want 2 (hint match), got %d (Server=%q)",
			candidates[0].Priority, candidates[0].ServerHdr)
	}
}

// TestFilterHTTP_NoHintMatch gives priority < 2 when the Server header does
// not match any hint.
func TestFilterHTTP_NoHintMatch(t *testing.T) {
	_, ip, port := startTestServer(t, "apache/2.4") // not in MCPServerHints

	dict := config.DefaultDictSet()
	ports := []PortResult{{IP: ip, Port: port, Open: true}}
	candidates := FilterHTTP(context.Background(), ports, 3000, 10, dict)

	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Priority >= 2 {
		t.Errorf("priority: want <2 for unknown server, got %d", candidates[0].Priority)
	}
}

// TestFilterHTTP_CustomHints verifies that a custom DictSet with a different
// hint list changes priority assignment.
func TestFilterHTTP_CustomHints(t *testing.T) {
	_, ip, port := startTestServer(t, "my-custom-agent-server/1.0")

	dict := config.DefaultDictSet()
	dict.MCPServerHints = []string{"my-custom-agent-server"} // override

	ports := []PortResult{{IP: ip, Port: port, Open: true}}
	candidates := FilterHTTP(context.Background(), ports, 3000, 10, dict)

	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Priority != 2 {
		t.Errorf("priority: want 2 for custom hint match, got %d", candidates[0].Priority)
	}
}

// TestFilterHTTP_HTTPSPortsInference verifies that a port in dict.HTTPSPorts
// gets the https:// scheme in the generated BaseURL.
// We skip the real TLS dial and just verify the BaseURL scheme — for that we
// need to use proto override via PortResult.Proto instead, since the test
// server is plain HTTP. The dict.HTTPSPorts inference path only fires when
// Proto is "". This test checks the logic by substituting a dict that does NOT
// list the port as HTTPS, ensuring http:// is chosen.
func TestFilterHTTP_HTTPSPortsInference_HTTP(t *testing.T) {
	_, ip, port := startTestServer(t, "")

	dict := config.DefaultDictSet()
	// Remove port from HTTPSPorts so it infers http://
	delete(dict.HTTPSPorts, port)

	ports := []PortResult{{IP: ip, Port: port, Open: true}}
	candidates := FilterHTTP(context.Background(), ports, 3000, 10, dict)

	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	want := fmt.Sprintf("http://%s:%d", ip, port)
	if candidates[0].BaseURL != want {
		t.Errorf("BaseURL: want %q, got %q", want, candidates[0].BaseURL)
	}
}

// TestFilterHTTP_NilDict falls back to DefaultDictSet without panic.
func TestFilterHTTP_NilDict(t *testing.T) {
	_, ip, port := startTestServer(t, "uvicorn")

	ports := []PortResult{{IP: ip, Port: port, Open: true}}
	// nil dict must not panic and must still work
	candidates := FilterHTTP(context.Background(), ports, 3000, 10, nil)

	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate with nil dict, got %d", len(candidates))
	}
}

func TestFilterHTTPUsesHTTPProxy(t *testing.T) {
	proxyHit := make(chan string, 1)
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.IsAbs() {
			proxyHit <- r.URL.String()
		}
		w.Header().Set("Server", "uvicorn")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(proxySrv.Close)
	t.Cleanup(func() { _ = netproxy.Configure("") })

	if err := netproxy.Configure(proxySrv.URL); err != nil {
		t.Fatalf("Configure proxy: %v", err)
	}

	dict := config.DefaultDictSet()
	delete(dict.HTTPSPorts, 45678)
	ports := []PortResult{{IP: "203.0.113.10", Port: 45678, Open: true}}
	candidates := FilterHTTP(context.Background(), ports, 3000, 10, dict)

	if len(candidates) != 1 {
		t.Fatalf("expected proxy-backed candidate, got %d", len(candidates))
	}
	if candidates[0].Priority != 2 {
		t.Fatalf("priority = %d, want 2 from proxy response server hint", candidates[0].Priority)
	}
	select {
	case got := <-proxyHit:
		want := "http://203.0.113.10:45678/"
		if got != want {
			t.Fatalf("proxy saw URL %q, want %q", got, want)
		}
	default:
		t.Fatal("proxy was not used")
	}
}
