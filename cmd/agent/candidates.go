package main

import (
	"net"
	"net/netip"
	"sort"

	"gowireguard/internal/proto"
)

// Caps keep the payload bounded on multi-homed boxes (a Docker host
// can carry dozens of bridge addresses); the server caps again at 8.
const (
	maxHostCandidates  = 4
	maxHost6Candidates = 2
)

// cgnat is 100.64.0.0/10 (RFC 6598): carrier-grade NAT space. An
// address here is doubly unreachable from outside AND likely to be
// mesh/VPN overlay space (the default overlay lives inside it), so it
// is never a useful candidate.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// gatherLocalCandidates returns host/host6 candidates for this node's
// WireGuard socket: interface addresses paired with the listen port.
// This is what makes two peers behind the SAME NAT (or on the same
// Docker host) connect directly — their STUN/observed addresses are
// the shared WAN IP, which only works if the router hairpins, while
// these are the addresses that actually route on the local wire.
//
// Excluded: loopback, link-local, CGNAT space, the mesh's own overlay
// prefixes and interface (those route through the tunnel being set
// up), and ULA IPv6 (no way to tell site ULA from another mesh's; the
// same-LAN case is covered by the v4 candidates), plus SLAAC privacy
// (temporary) v6 addresses, which rotate and make dead endpoints.
//
// advertiseV6 gates global-IPv6 (host6) candidates: wgmesh has no v6
// reachability signal (no v6 STUN or relay-observed mapping), so it
// cannot tell a firewall-open global v6 from a closed one. It only
// advertises v6 when this agent manages its own firewall — i.e. it
// actually opened the port on both families. Hosts with a hand-managed
// firewall (--manage-firewall=false) that never opened v6 inbound stop
// handing peers unreachable v6 candidates to waste probes on.
//
// WireGuard binds dual-stack, so the one listen port serves every
// address.
func gatherLocalCandidates(listenPort int, advertiseV6 bool, overlays ...netip.Prefix) []proto.AgentCandidate {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	temporary := temporaryV6Addrs()

	var v4, v6 []netip.Addr

	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Name == ifaceName {
			continue
		}

		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()

			if !candidateAddr(addr, overlays) {
				continue
			}

			if addr.Is4() {
				v4 = append(v4, addr)
			} else if advertiseV6 && !temporary[addr] {
				v6 = append(v6, addr)
			}
		}
	}

	// Deterministic order so the reported list is stable across ticks —
	// the server-side candidate digest re-arms probing on CHANGE, and a
	// map-ordered list would fake one every report.
	sort.Slice(v4, func(i, j int) bool { return v4[i].Less(v4[j]) })
	sort.Slice(v6, func(i, j int) bool { return v6[i].Less(v6[j]) })

	if len(v4) > maxHostCandidates {
		v4 = v4[:maxHostCandidates]
	}
	if len(v6) > maxHost6Candidates {
		v6 = v6[:maxHost6Candidates]
	}

	out := make([]proto.AgentCandidate, 0, len(v4)+len(v6))
	for _, a := range v4 {
		out = append(out, proto.AgentCandidate{
			Endpoint: netip.AddrPortFrom(a, uint16(listenPort)).String(),
			Type:     "host",
		})
	}
	for _, a := range v6 {
		out = append(out, proto.AgentCandidate{
			Endpoint: netip.AddrPortFrom(a, uint16(listenPort)).String(),
			Type:     "host6",
		})
	}

	return out
}

// candidateAddr reports whether addr is worth advertising as a way to
// reach this host's WireGuard socket.
func candidateAddr(addr netip.Addr, overlays []netip.Prefix) bool {
	if !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}

	for _, p := range overlays {
		if p.IsValid() && p.Contains(addr) {
			return false
		}
	}

	if addr.Is4() {
		return !cgnat.Contains(addr)
	}

	// IPv6: global unicast only (2000::/3 in practice); IsPrivate
	// catches ULA fc00::/7.
	return addr.IsGlobalUnicast() && !addr.IsPrivate()
}
