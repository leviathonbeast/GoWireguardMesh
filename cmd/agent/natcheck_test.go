package main

import (
	"net"
	"strconv"
	"testing"

	"github.com/pion/stun/v3"
)

// testSTUNServer answers binding requests on a loopback socket,
// standing in for the mesh relay's STUN responder.
func testSTUNServer(t *testing.T) *net.UDPAddr {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("bind stun server: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			req := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if err := req.Decode(); err != nil || req.Type != stun.BindingRequest {
				continue
			}

			resp, err := stun.Build(
				stun.NewTransactionIDSetter(req.TransactionID),
				stun.BindingSuccess,
				&stun.XORMappedAddress{IP: src.IP, Port: src.Port},
				stun.Fingerprint,
			)
			if err != nil {
				continue
			}

			_, _ = conn.WriteToUDP(resp.Raw, src)
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr)
}

func TestCheckNATClassifiesEasyMapping(t *testing.T) {
	s1 := testSTUNServer(t)
	s2 := testSTUNServer(t)

	mapped, natType, err := checkNAT([]string{s1.String(), s2.String()})
	if err != nil {
		t.Fatalf("checkNAT: %v", err)
	}

	// No NAT between the loopback sockets: both servers see the same
	// source, which classifies as endpoint-independent.
	if natType != "easy" {
		t.Fatalf("natType = %q, want easy", natType)
	}
	if !mapped.IsValid() || !mapped.Addr().IsLoopback() {
		t.Fatalf("mapped = %v, want loopback source", mapped)
	}
}

func TestCheckNATSingleServerLeavesTypeUnknown(t *testing.T) {
	s1 := testSTUNServer(t)

	mapped, natType, err := checkNAT([]string{s1.String()})
	if err != nil {
		t.Fatalf("checkNAT: %v", err)
	}
	if natType != "" {
		t.Fatalf("natType = %q, want unknown with one server", natType)
	}
	if !mapped.IsValid() {
		t.Fatalf("mapped invalid")
	}
}

func TestCheckNATNoServers(t *testing.T) {
	if _, _, err := checkNAT(nil); err == nil {
		t.Fatal("checkNAT(nil) succeeded, want error")
	}
}

func TestDiscoverPublicEndpointUsesListenPortMapping(t *testing.T) {
	s1 := testSTUNServer(t)

	// Grab a free port to stand in for the WireGuard listen port.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("probe bind: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	got, err := discoverPublicEndpoint(s1.String(), port)
	if err != nil {
		t.Fatalf("discoverPublicEndpoint: %v", err)
	}

	_, gotPort, err := net.SplitHostPort(got)
	if err != nil {
		t.Fatalf("bad endpoint %q: %v", got, err)
	}
	if gotPort != strconv.Itoa(port) {
		t.Fatalf("endpoint port = %s, want %d", gotPort, port)
	}
}
