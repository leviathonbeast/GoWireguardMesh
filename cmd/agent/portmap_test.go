package main

import (
	"net/netip"
	"testing"
)

func TestPublicV4(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.9", true},
		{"8.8.8.8", true},
		{"192.168.1.1", false}, // private: double NAT
		{"10.44.0.1", false},
		{"172.16.5.5", false},
		{"100.64.0.1", false}, // CGNAT
		{"127.0.0.1", false},
		{"169.254.0.5", false},
		{"0.0.0.0", false},
		{"2001:db8::1", false}, // v6 mappings are not what we asked for
	}

	for _, tt := range tests {
		if got := publicV4(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("publicV4(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
