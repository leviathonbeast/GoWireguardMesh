package relay

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// stunRoundTrip sends a binding request from client to server and
// returns the mapped address the responder reported.
func stunRoundTrip(t *testing.T, client *net.UDPConn, server net.Addr) netip.AddrPort {
	t.Helper()

	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := client.WriteTo(req.Raw, server); err != nil {
		t.Fatalf("send binding request: %v", err)
	}

	buf := make([]byte, 1500)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read binding response: %v", err)
	}

	res := &stun.Message{Raw: buf[:n]}
	if err := res.Decode(); err != nil {
		t.Fatalf("decode binding response: %v", err)
	}
	if res.Type != stun.BindingSuccess {
		t.Fatalf("response type = %v, want binding success", res.Type)
	}
	if res.TransactionID != req.TransactionID {
		t.Fatalf("transaction id mismatch")
	}

	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(res); err != nil {
		t.Fatalf("no mapped address: %v", err)
	}

	addr, ok := netip.AddrFromSlice(mapped.IP)
	if !ok {
		t.Fatalf("bad mapped ip %v", mapped.IP)
	}

	return netip.AddrPortFrom(addr.Unmap(), uint16(mapped.Port))
}

func TestServeSTUNAnswersBindingRequest(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	defer server.Close()

	go serveSTUN(server)

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Close()

	mapped := stunRoundTrip(t, client, server.LocalAddr())

	want := client.LocalAddr().(*net.UDPAddr)
	if mapped.Port() != uint16(want.Port) || mapped.Addr().String() != want.IP.String() {
		t.Fatalf("mapped = %v, want %v", mapped, want)
	}
}

func TestServeSTUNIgnoresNonSTUN(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	defer server.Close()

	go serveSTUN(server)

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Close()

	// Garbage first: no reply may come back for it.
	if _, err := client.WriteTo([]byte("not stun at all"), server.LocalAddr()); err != nil {
		t.Fatalf("send garbage: %v", err)
	}

	// A real request afterwards still gets answered (the loop survived).
	mapped := stunRoundTrip(t, client, server.LocalAddr())
	if mapped.Port() != uint16(client.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatalf("mapped port = %d, want client port", mapped.Port())
	}
}

func TestNewSTUNResponderServesPortPair(t *testing.T) {
	// Find a free adjacent pair by binding :0 and trying its neighbor.
	var responder *STUNResponder
	var port int

	for attempt := 0; attempt < 10; attempt++ {
		probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("probe bind: %v", err)
		}

		port = probe.LocalAddr().(*net.UDPAddr).Port
		probe.Close()

		responder, err = NewSTUNResponder(net.IPv4(127, 0, 0, 1), port)
		if err == nil {
			break
		}
		responder = nil
	}

	if responder == nil {
		t.Skip("no adjacent free udp port pair found")
	}
	defer responder.Close()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Close()

	first := stunRoundTrip(t, client, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	second := stunRoundTrip(t, client, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port + 1})

	// Same socket, no NAT in between: both ports must report the same
	// mapping — the "easy NAT" signature agents test for.
	if first != second {
		t.Fatalf("mapped addresses differ across ports: %v vs %v", first, second)
	}
}

func TestObservedReportsLatchedSources(t *testing.T) {
	s, err := New(Config{DataIP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	defer s.Close()

	portA, _, err := s.Allocate("pair-observed")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Close()

	// A WireGuard handshake-initiation-shaped datagram latches leg A.
	pkt := make([]byte, 148)
	pkt[0] = msgInitiation

	if _, err := client.WriteTo(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portA}); err != nil {
		t.Fatalf("send wg-shaped packet: %v", err)
	}

	want := client.LocalAddr().(*net.UDPAddr)

	deadline := time.Now().Add(2 * time.Second)
	for {
		srcA, srcB, ok := s.Observed("pair-observed")
		if !ok {
			t.Fatalf("Observed: pair not found")
		}

		if srcA.IsValid() {
			if int(srcA.Port()) != want.Port {
				t.Fatalf("observed srcA = %v, want port %d", srcA, want.Port)
			}
			if srcB.IsValid() {
				t.Fatalf("srcB = %v, want unset (leg B never checked in)", srcB)
			}
			break
		}

		if time.Now().After(deadline) {
			t.Fatalf("leg A source never latched")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, _, ok := s.Observed("no-such-pair"); ok {
		t.Fatalf("Observed(no-such-pair) = ok, want false")
	}
}
