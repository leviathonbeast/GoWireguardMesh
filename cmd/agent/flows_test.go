package main

import (
	"net/netip"
	"testing"

	"gowireguard/internal/proto"
)

type fakeFlowDumper struct{ flows []ctFlow }

func (f *fakeFlowDumper) Dump() ([]ctFlow, error) { return f.flows, nil }
func (f *fakeFlowDumper) Close() error            { return nil }

func TestOrientFlow(t *testing.T) {
	a := netip.MustParseAddr("100.78.0.1")
	b := netip.MustParseAddr("100.78.0.4")

	cases := []struct {
		name                   string
		src                    netip.Addr
		sport                  uint16
		dst                    netip.Addr
		dport                  uint16
		wantClient, wantServer netip.Addr
		wantPort               uint16
		wantFlipped            bool
	}{
		{"client is src", a, 51722, b, 4040, a, b, 4040, false},
		{"client is dst", b, 4040, a, 51722, a, b, 4040, true},
		{"both ephemeral -> lower is server", a, 40000, b, 50000, b, a, 40000, true},
		{"both well-known -> lower is server", a, 443, b, 80, a, b, 80, false},
	}

	for _, c := range cases {
		client, server, port, flipped := orientFlow(c.src, c.sport, c.dst, c.dport)
		if client != c.wantClient || server != c.wantServer || port != c.wantPort || flipped != c.wantFlipped {
			t.Fatalf("%s: orientFlow = %v -> %v:%d flipped=%v, want %v -> %v:%d flipped=%v",
				c.name, client, server, port, flipped, c.wantClient, c.wantServer, c.wantPort, c.wantFlipped)
		}
	}
}

func newFlowTestReporter(flows []ctFlow) *telemetryReporter {
	return &telemetryReporter{
		network:      netip.MustParsePrefix("100.78.0.0/16"),
		prevFlow:     make(map[flowKey]flowCounters),
		pendingFlows: make(map[flowKey]*proto.FlowRecord),
		ct:           &fakeFlowDumper{flows: flows},
	}
}

func onlyPending(t *testing.T, tel *telemetryReporter) *proto.FlowRecord {
	t.Helper()
	if len(tel.pendingFlows) != 1 {
		t.Fatalf("pendingFlows = %d, want 1 aggregated record", len(tel.pendingFlows))
	}
	for _, r := range tel.pendingFlows {
		return r
	}
	return nil
}

func TestCollectFlowsAggregatesByService(t *testing.T) {
	traefik := netip.MustParseAddr("100.78.0.1")
	muse := netip.MustParseAddr("100.78.0.4")

	// Two health-check connections: different ephemeral ports, same :4040.
	tel := newFlowTestReporter([]ctFlow{
		{protocol: 6, src: traefik, srcPort: 51722, dst: muse, dstPort: 4040, txBytes: 100, txPackets: 1, rxBytes: 40, rxPackets: 1},
		{protocol: 6, src: traefik, srcPort: 52000, dst: muse, dstPort: 4040, txBytes: 60, txPackets: 1, rxBytes: 20, rxPackets: 1},
	})
	tel.collectFlows()

	rec := onlyPending(t, tel)
	if rec.SrcIP != "100.78.0.1" || rec.SrcPort != 0 || rec.DstIP != "100.78.0.4" || rec.DstPort != 4040 {
		t.Fatalf("record = %s:%d -> %s:%d, want 100.78.0.1:0 -> 100.78.0.4:4040", rec.SrcIP, rec.SrcPort, rec.DstIP, rec.DstPort)
	}
	if rec.TxBytes != 160 || rec.RxBytes != 60 {
		t.Fatalf("aggregated bytes tx=%d rx=%d, want tx=160 rx=60", rec.TxBytes, rec.RxBytes)
	}
}

func TestCollectFlowsOrientsServerSideConsistently(t *testing.T) {
	traefik := netip.MustParseAddr("100.78.0.1")
	muse := netip.MustParseAddr("100.78.0.4")

	// As reported from muse's side (capture orients local as src): the
	// server (muse:4040) is src. After orientation it must read the same
	// as traefik's view — client(traefik) -> server(muse:4040) — with
	// tx/rx swapped.
	tel := newFlowTestReporter([]ctFlow{
		{protocol: 6, src: muse, srcPort: 4040, dst: traefik, dstPort: 51722, txBytes: 200, txPackets: 2, rxBytes: 30, rxPackets: 1},
	})
	tel.collectFlows()

	rec := onlyPending(t, tel)
	if rec.SrcIP != "100.78.0.1" || rec.DstIP != "100.78.0.4" || rec.DstPort != 4040 {
		t.Fatalf("orientation = %s -> %s:%d, want 100.78.0.1 -> 100.78.0.4:4040", rec.SrcIP, rec.DstIP, rec.DstPort)
	}
	if rec.TxBytes != 30 || rec.RxBytes != 200 {
		t.Fatalf("swapped bytes tx=%d rx=%d, want tx=30 rx=200 (client->server)", rec.TxBytes, rec.RxBytes)
	}
}
