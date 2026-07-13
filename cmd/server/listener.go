package main

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// PROXY protocol restores real client addresses when a TCP/SNI
// passthrough proxy (Traefik HostSNI + passthrough) fronts the
// listener: the proxy prepends the original source address to the
// stream, and rate limiting, the access log, and the audit log see
// the agent instead of the proxy.
//
// Honoring the header is an identity claim, so it follows the same
// rule as X-Forwarded-For: believed only from --trusted-proxies
// sources. Anyone else's header is parsed and discarded (IGNORE), so
// a direct client can neither spoof an address nor break its own
// connection by sending one.

// proxyHeaderPolicy decides per connection whether the PROXY header
// is honored, keyed on the immediate peer address.
func proxyHeaderPolicy(trusted []netip.Prefix) proxyproto.ConnPolicyFunc {
	return func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		host, _, err := net.SplitHostPort(opts.Upstream.String())
		if err != nil {
			return proxyproto.IGNORE, nil
		}

		addr, err := netip.ParseAddr(host)
		if err != nil {
			return proxyproto.IGNORE, nil
		}

		addr = addr.Unmap()
		for _, p := range trusted {
			if p.Contains(addr) {
				return proxyproto.USE, nil
			}
		}

		return proxyproto.IGNORE, nil
	}
}

// buildListener opens the TCP listener, wrapped for PROXY protocol
// when enabled. TLS stays the caller's job (http.Server.ServeTLS),
// so the header is read from the plaintext prefix of the stream —
// where the proxy writes it — not from inside the TLS session.
func buildListener(addr string, proxyProto bool, trusted []netip.Prefix) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	if !proxyProto {
		return ln, nil
	}

	return &proxyproto.Listener{
		Listener:          ln,
		ConnPolicy:        proxyHeaderPolicy(trusted),
		ReadHeaderTimeout: 5 * time.Second,
	}, nil
}
