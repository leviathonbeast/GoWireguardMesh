//go:build linux

package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// ipv4Packet builds a minimal IPv4 + TCP/UDP packet for the parser tests.
func ipv4Packet(proto uint8, src, dst netip.Addr, sport, dport uint16, total int) []byte {
	if total < 28 {
		total = 28
	}
	p := make([]byte, total)
	p[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	p[9] = proto
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)

	return p
}

func newTestCaptureDumper(self netip.Addr) *captureDumper {
	return &captureDumper{
		fd:    -1,
		self4: self,
		flows: make(map[flowKey]*flowAccum),
	}
}

func TestParseFlowTupleIPv4UDP(t *testing.T) {
	src := netip.MustParseAddr("100.78.0.4")
	dst := netip.MustParseAddr("100.78.0.1")

	proto, gs, sp, gd, dp, ok := parseFlowTuple(ipv4Packet(17, src, dst, 12345, 53, 40))
	if !ok {
		t.Fatal("parseFlowTuple returned !ok for a valid IPv4/UDP packet")
	}
	if proto != 17 || gs != src || gd != dst || sp != 12345 || dp != 53 {
		t.Fatalf("tuple = %d %v:%d -> %v:%d, want 17 %v:12345 -> %v:53", proto, gs, sp, gd, dp, src, dst)
	}
}

func TestParseFlowTupleIPv6TCP(t *testing.T) {
	src := netip.MustParseAddr("fd00:100:64::4")
	dst := netip.MustParseAddr("fd00:100:64::1")

	p := make([]byte, 60)
	p[0] = 0x60 // version 6
	p[6] = 6    // next header = TCP
	copy(p[8:24], src.AsSlice())
	copy(p[24:40], dst.AsSlice())
	binary.BigEndian.PutUint16(p[40:42], 40000)
	binary.BigEndian.PutUint16(p[42:44], 443)

	proto, gs, sp, gd, dp, ok := parseFlowTuple(p)
	if !ok || proto != 6 || gs != src || gd != dst || sp != 40000 || dp != 443 {
		t.Fatalf("ipv6/tcp tuple = ok=%v %d %v:%d -> %v:%d", ok, proto, gs, sp, gd, dp)
	}
}

func TestParseFlowTupleRejectsGarbage(t *testing.T) {
	if _, _, _, _, _, ok := parseFlowTuple([]byte{0x00}); ok {
		t.Fatal("parseFlowTuple accepted a 1-byte packet")
	}
	if _, _, _, _, _, ok := parseFlowTuple(make([]byte, 10)); ok {
		t.Fatal("parseFlowTuple accepted a too-short IPv4 packet")
	}
}

func TestCaptureAccountDirectionAndKey(t *testing.T) {
	self := netip.MustParseAddr("100.78.0.4")
	peer := netip.MustParseAddr("100.78.0.1")
	c := newTestCaptureDumper(self)

	// Outbound: self is src -> counts as tx.
	c.account(ipv4Packet(17, self, peer, 12345, 53, 100), 100)
	// Inbound reply: self is dst -> same flow key, counts as rx.
	c.account(ipv4Packet(17, peer, self, 53, 12345, 200), 200)

	flows, _ := c.Dump()
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1 (both directions share one key)", len(flows))
	}

	f := flows[0]
	if f.src != self || f.dst != peer || f.srcPort != 12345 || f.dstPort != 53 {
		t.Fatalf("flow oriented wrong: %v:%d -> %v:%d, want local as src", f.src, f.srcPort, f.dst, f.dstPort)
	}
	if f.txBytes != 100 || f.txPackets != 1 || f.rxBytes != 200 || f.rxPackets != 1 {
		t.Fatalf("counters = tx %d/%d rx %d/%d, want tx 100/1 rx 200/1", f.txBytes, f.txPackets, f.rxBytes, f.rxPackets)
	}
}

func TestCaptureIgnoresForeignTraffic(t *testing.T) {
	c := newTestCaptureDumper(netip.MustParseAddr("100.78.0.4"))
	a := netip.MustParseAddr("100.78.0.1")
	b := netip.MustParseAddr("100.78.0.2")

	c.account(ipv4Packet(17, a, b, 1, 2, 100), 100) // neither end is self

	if flows, _ := c.Dump(); len(flows) != 0 {
		t.Fatalf("recorded a flow with no local endpoint: %d", len(flows))
	}
}

func TestCaptureEvictsIdleFlows(t *testing.T) {
	self := netip.MustParseAddr("100.78.0.4")
	peer := netip.MustParseAddr("100.78.0.1")
	c := newTestCaptureDumper(self)

	c.account(ipv4Packet(17, self, peer, 12345, 53, 100), 100)
	for _, a := range c.flows {
		a.lastSeen = time.Now().Add(-2 * captureFlowTTL) // backdate past the TTL
	}

	if flows, _ := c.Dump(); len(flows) != 0 {
		t.Fatalf("stale flow not evicted: %d", len(flows))
	}
}
