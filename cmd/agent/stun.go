package main

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/pion/stun/v3"
)

// discoverPublicEndpoint asks a STUN server how this host's
// listenPort appears from the internet, returning "ip:port".
//
// It must run while the WireGuard interface does NOT exist: it binds
// listenPort itself so the NAT mapping it creates is the same one
// WireGuard traffic will use once the kernel takes the port over.
// For endpoint-independent ("full cone"-ish) NATs that mapping stays
// valid; symmetric NATs will defeat this and need the relay.
func discoverPublicEndpoint(stunServer string, listenPort int) (string, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: listenPort})
	if err != nil {
		return "", fmt.Errorf("bind udp port %d for STUN: %w", listenPort, err)
	}
	defer conn.Close()

	mapped, err := stunQuery(conn, stunServer, 5*time.Second)
	if err != nil {
		return "", err
	}

	return mapped.String(), nil
}

// stunQuery sends one binding request from conn and returns the mapped
// address the server saw. The conn is reusable across queries (each
// call reads until it sees its own transaction ID or times out).
func stunQuery(conn *net.UDPConn, stunServer string, timeout time.Duration) (netip.AddrPort, error) {
	serverAddr, err := net.ResolveUDPAddr("udp4", stunServer)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve STUN server %q: %w", stunServer, err)
	}

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return netip.AddrPort{}, fmt.Errorf("set STUN deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{})

	if _, err := conn.WriteTo(msg.Raw, serverAddr); err != nil {
		return netip.AddrPort{}, fmt.Errorf("send STUN request to %q: %w", stunServer, err)
	}

	buf := make([]byte, 1500)

	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("read STUN response from %q: %w", stunServer, err)
		}

		res := &stun.Message{Raw: buf[:n]}
		if err := res.Decode(); err != nil {
			continue // not STUN (or garbage); keep waiting for ours
		}

		if res.TransactionID != msg.TransactionID {
			continue // a late answer to an earlier query
		}

		var mapped stun.XORMappedAddress
		if err := mapped.GetFrom(res); err != nil {
			return netip.AddrPort{}, fmt.Errorf("no mapped address in STUN response: %w", err)
		}

		addr, ok := netip.AddrFromSlice(mapped.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("bad mapped address %v", mapped.IP)
		}

		return netip.AddrPortFrom(addr.Unmap(), uint16(mapped.Port)), nil
	}
}

// checkNAT probes STUN servers from one throwaway ephemeral socket.
// The kernel owns the WireGuard port while the agent runs, so this
// cannot re-measure that port's mapping directly — it measures the
// NAT's *behavior* and the current public IP, which is what the
// periodic refresh needs:
//
//   - mapped is how the ephemeral socket appears publicly. Its IP is
//     trustworthy for "did our public IP change"; its PORT belongs to
//     the ephemeral socket and must never be advertised.
//   - natType classifies mapping behavior when servers offers two
//     endpoints (the mesh relay's STUN port pair): querying both from
//     the SAME socket, identical mapped addresses mean the mapping is
//     endpoint-independent ("easy" — hole-punchable), differing ones
//     mean endpoint-dependent ("hard"/symmetric). With one server the
//     type is "" (unknown).
func checkNAT(servers []string) (mapped netip.AddrPort, natType string, err error) {
	if len(servers) == 0 {
		return netip.AddrPort{}, "", fmt.Errorf("no STUN servers configured")
	}

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return netip.AddrPort{}, "", fmt.Errorf("bind ephemeral socket for STUN: %w", err)
	}
	defer conn.Close()

	first, err := stunQuery(conn, servers[0], 3*time.Second)
	if err != nil {
		return netip.AddrPort{}, "", err
	}

	if len(servers) < 2 {
		return first, "", nil
	}

	second, err := stunQuery(conn, servers[1], 3*time.Second)
	if err != nil {
		// The first answer still refreshes the public IP; only the
		// classification is lost.
		return first, "", nil
	}

	natType = "easy"
	if first != second {
		natType = "hard"
	}

	return first, natType, nil
}
