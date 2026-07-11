package relay

import (
	"net"
	"testing"
	"time"
)

// wgPacket builds a datagram of the given WireGuard message type at a
// valid size for that type.
func wgPacket(msgType byte, size int) []byte {
	b := make([]byte, size)
	b[0] = msgType
	return b
}

func TestWGShaped(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"initiation", wgPacket(msgInitiation, 148), true},
		{"initiation wrong size", wgPacket(msgInitiation, 147), false},
		{"response", wgPacket(msgResponse, 92), true},
		{"response wrong size", wgPacket(msgResponse, 148), false},
		{"cookie", wgPacket(msgCookie, 64), true},
		{"transport keepalive", wgPacket(msgTransport, 32), true},
		{"transport data", wgPacket(msgTransport, 1400), true},
		{"transport too short", wgPacket(msgTransport, 31), false},
		{"unknown type", wgPacket(9, 148), false},
		{"type zero", wgPacket(0, 148), false},
		{"reserved bytes set", append([]byte{4, 1, 0, 0}, make([]byte, 60)...), false},
		{"empty", nil, false},
		{"tiny", []byte{4}, false},
		{"dns-ish probe", []byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wgShaped(tc.pkt); got != tc.want {
				t.Fatalf("wgShaped(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// relayTestPair allocates a forwarding pair on loopback and returns
// two client sockets already checked in on their legs, plus the pair's
// two relay addresses.
func relayTestPair(t *testing.T) (peerA, peerB *net.UDPConn, relayA, relayB *net.UDPAddr) {
	t.Helper()

	s, err := New(Config{DataIP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)

	portA, portB, err := s.Allocate("test-pair")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	relayA = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portA}
	relayB = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portB}

	peerA = clientSocket(t)
	peerB = clientSocket(t)

	// Check in both legs (keepalive-shaped), like WireGuard's
	// persistent keepalives would.
	sendTo(t, peerA, relayA, wgPacket(msgTransport, 32))
	sendTo(t, peerB, relayB, wgPacket(msgTransport, 32))

	// A's first keepalive raced B's check-in, so it may or may not have
	// been delivered; settle the pair by draining until quiet.
	drain(peerA)
	drain(peerB)

	return peerA, peerB, relayA, relayB
}

func clientSocket(t *testing.T) *net.UDPConn {
	t.Helper()

	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	return c
}

func sendTo(t *testing.T, c *net.UDPConn, dst *net.UDPAddr, pkt []byte) {
	t.Helper()

	if _, err := c.WriteToUDP(pkt, dst); err != nil {
		t.Fatalf("send: %v", err)
	}
	// Give the relay's forward goroutine time to process before the
	// next step depends on its state.
	time.Sleep(20 * time.Millisecond)
}

func recvOne(t *testing.T, c *net.UDPConn) ([]byte, bool) {
	t.Helper()

	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

func drain(c *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, _, err := c.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

func TestRelayForwardsWireGuardTraffic(t *testing.T) {
	peerA, peerB, relayA, relayB := relayTestPair(t)

	data := wgPacket(msgTransport, 128)
	data[10] = 0xAB
	sendTo(t, peerA, relayA, data)

	got, ok := recvOne(t, peerB)
	if !ok {
		t.Fatal("peer B did not receive A's packet")
	}
	if len(got) != 128 || got[10] != 0xAB {
		t.Fatalf("packet mangled: len=%d", len(got))
	}

	sendTo(t, peerB, relayB, wgPacket(msgTransport, 64))
	if _, ok := recvOne(t, peerA); !ok {
		t.Fatal("peer A did not receive B's packet")
	}
}

func TestRelayDropsNonWireGuardJunk(t *testing.T) {
	peerA, peerB, relayA, relayB := relayTestPair(t)

	scanner := clientSocket(t)

	// A scanner probe must not reach either peer's WireGuard socket.
	sendTo(t, scanner, relayB, []byte("GET / HTTP/1.1\r\n\r\n"))
	if pkt, ok := recvOne(t, peerA); ok {
		t.Fatalf("junk was forwarded to peer A: %q", pkt)
	}

	// And it must not have disturbed the pair: A -> B still works.
	sendTo(t, peerA, relayA, wgPacket(msgTransport, 32))
	if _, ok := recvOne(t, peerB); !ok {
		t.Fatal("pair broken after junk probe")
	}
}

func TestRelayPinsAgainstDataPacketHijack(t *testing.T) {
	peerA, peerB, relayA, relayB := relayTestPair(t)

	attacker := clientSocket(t)

	// The attacker sends a perfectly WireGuard-shaped *data* packet to
	// B's leg. It must not become the recorded address for that leg.
	sendTo(t, attacker, relayB, wgPacket(msgTransport, 64))
	drain(peerA)
	drain(attacker)

	// A's traffic must still reach the real peer B, not the attacker.
	sendTo(t, peerA, relayA, wgPacket(msgTransport, 96))

	if _, ok := recvOne(t, attacker); ok {
		t.Fatal("attacker hijacked the ciphertext stream with a spoofed data packet")
	}
	if _, ok := recvOne(t, peerB); !ok {
		t.Fatal("peer B stopped receiving after attempted hijack")
	}
}

func TestRelayAllowsRoamingViaHandshake(t *testing.T) {
	peerA, peerB, relayA, relayB := relayTestPair(t)
	_ = peerB

	// Peer B roams: a new socket (new NAT mapping) re-handshakes, as
	// WireGuard does when replies stop arriving.
	roamed := clientSocket(t)
	sendTo(t, roamed, relayB, wgPacket(msgInitiation, 148))
	drain(peerA)
	drain(roamed)

	sendTo(t, peerA, relayA, wgPacket(msgTransport, 96))

	if _, ok := recvOne(t, roamed); !ok {
		t.Fatal("roamed peer did not receive traffic after re-handshake")
	}
}
