//go:build linux

package main

import "testing"

func TestParseProcRoute(t *testing.T) {
	// Real-world shape: header line, non-default routes, then the
	// default route with a little-endian hex gateway (192.168.2.1).
	content := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t0028A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
		"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"

	gw := parseProcRoute(content)
	if gw == nil {
		t.Fatal("parseProcRoute returned nil")
	}
	if got := gw.String(); got != "192.168.2.1" {
		t.Fatalf("gateway = %s, want 192.168.2.1", got)
	}
}

func TestParseProcRouteNoDefault(t *testing.T) {
	content := "Iface\tDestination\tGateway \tFlags\n" +
		"eth0\t0028A8C0\t00000000\t0001\n"

	if gw := parseProcRoute(content); gw != nil {
		t.Fatalf("parseProcRoute = %v, want nil without a default route", gw)
	}
}
