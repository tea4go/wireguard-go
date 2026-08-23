//go:build windows

package conn

import "testing"

func TestWinRingBindParseEndpointAllowsHostname(t *testing.T) {
	bind := NewWinRingBind()
	ep, err := bind.ParseEndpoint("localhost:51820")
	if err != nil {
		t.Fatalf("ParseEndpoint returned error: %v", err)
	}
	if ep == nil {
		t.Fatal("ParseEndpoint returned nil endpoint")
	}
	if !ep.DstIP().IsValid() {
		t.Fatalf("expected resolved destination IP, got %v", ep.DstIP())
	}
}

func TestWinRingBindParseEndpointDefersHostnameResolution(t *testing.T) {
	bind := NewWinRingBind()
	ep, err := bind.ParseEndpoint("this-domain-should-never-exist.invalid:51820")
	if err != nil {
		t.Fatalf("ParseEndpoint returned error: %v", err)
	}
	if got := ep.DstToString(); got != "this-domain-should-never-exist.invalid:51820" {
		t.Fatalf("expected original endpoint string, got %q", got)
	}
}
