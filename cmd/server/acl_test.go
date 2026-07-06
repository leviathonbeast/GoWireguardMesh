package main

import "testing"

func TestPeerRef(t *testing.T) {
	if got := peerRef(nil); got != "any" {
		t.Fatalf("peerRef(nil) = %q, want any", got)
	}

	id := int64(12)
	if got := peerRef(&id); got != "12" {
		t.Fatalf("peerRef(&12) = %q, want 12", got)
	}
}

func TestPortRange(t *testing.T) {
	p := func(v int64) *int64 { return &v }

	cases := []struct {
		name     string
		min, max *int64
		want     string
	}{
		{"both nil", nil, nil, "any"},
		{"equal", p(443), p(443), "443"},
		{"range", p(80), p(443), "80-443"},
		{"min only", p(80), nil, "80-any"},
		{"max only", nil, p(443), "any-443"},
	}

	for _, c := range cases {
		if got := portRange(c.min, c.max); got != c.want {
			t.Fatalf("%s: portRange = %q, want %q", c.name, got, c.want)
		}
	}
}
