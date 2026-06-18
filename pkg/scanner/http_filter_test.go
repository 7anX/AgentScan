package scanner

import "testing"

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
