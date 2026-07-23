package main

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/pion/stun/v3"
)

// discoverPublicEndpoint asks a STUN server how this host's IPv4
// listenPort appears from the internet, returning "ip:port".
//
// It must run while the WireGuard interface does NOT exist: it binds
// listenPort itself so the NAT mapping it creates is the same one
// WireGuard traffic will use once the kernel takes the port over.
// For endpoint-independent ("full cone"-ish) NATs that mapping stays
// valid; symmetric NATs will defeat this and need the relay.
func discoverPublicEndpoint(stunServer string, listenPort int) (string, error) {
	return discoverPublicEndpointFamily("udp4", stunServer, listenPort)
}

// discoverPublicEndpoint6 does the same over IPv6. Global v6 is almost
// never NATed, so the reflected address is normally this host's own
// global address — the point here is reachability: a value comes back
// only if the v6 STUN server could actually reach the bound port, which
// is exactly the signal for whether to advertise a v6 direct endpoint.
// No v6 connectivity (or a firewalled port) fails, and the caller
// simply omits the v6 candidate.
func discoverPublicEndpoint6(stunServer string, listenPort int) (string, error) {
	return discoverPublicEndpointFamily("udp6", stunServer, listenPort)
}

func discoverPublicEndpointFamily(network, stunServer string, listenPort int) (string, error) {
	conn, err := listenUDPMarked(network, &net.UDPAddr{Port: listenPort})
	if err != nil {
		return "", fmt.Errorf("bind %s port %d for STUN: %w", network, listenPort, err)
	}
	defer conn.Close()

	mapped, err := stunQueryFamily(conn, network, stunServer, 5*time.Second)
	if err != nil {
		return "", err
	}

	return mapped.String(), nil
}

// stunQuery sends one binding request from an IPv4 conn.
func stunQuery(conn *net.UDPConn, stunServer string, timeout time.Duration) (netip.AddrPort, error) {
	return stunQueryFamily(conn, "udp4", stunServer, timeout)
}

// stunQueryFamily sends one binding request from conn and returns the
// mapped address the server saw, resolving the server in the given
// family. The conn is reusable across queries (each call reads until it
// sees its own transaction ID or times out).
func stunQueryFamily(conn *net.UDPConn, network, stunServer string, timeout time.Duration) (netip.AddrPort, error) {
	serverAddr, err := net.ResolveUDPAddr(network, stunServer)
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

// stunReflexive6 probes a v6-capable STUN server from a throwaway
// ephemeral socket and returns the reflexive mapping. Used by the
// periodic refresh: the kernel owns the WG port, so this measures the
// current public v6 address (v6 is not NATed in practice, so the
// caller pairs the returned IP with the WG listen port). Failure means
// no usable global v6 right now — the v6 endpoint should be withdrawn.
func stunReflexive6(stunServer string) (netip.AddrPort, error) {
	conn, err := listenUDPMarked("udp6", nil)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bind ephemeral v6 socket for STUN: %w", err)
	}
	defer conn.Close()

	return stunQueryFamily(conn, "udp6", stunServer, 3*time.Second)
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

	conn, err := listenUDPMarked("udp4", nil)
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
