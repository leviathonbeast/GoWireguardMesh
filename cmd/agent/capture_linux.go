//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The capture flow source reads decrypted packets straight off the overlay
// interface and accumulates per-flow byte/packet counts in userspace. It is
// the fallback when conntrack byte accounting is unavailable — notably
// inside containers, where /proc/sys is read-only and nf_conntrack_acct
// cannot be enabled. It needs only CAP_NET_RAW, no sysctl.
const (
	captureSnapLen  = 128             // enough for IPv6 (40) + TCP/UDP ports
	captureFlowTTL  = 5 * time.Minute // drop flows idle at least this long
	captureMaxFlows = 8192            // hard cap on tracked flows
)

type flowAccum struct {
	txBytes, txPackets uint64
	rxBytes, rxPackets uint64
	lastSeen           time.Time
}

// captureDumper implements flowDumper by sniffing the overlay interface via
// an AF_PACKET socket. A background goroutine accumulates counts; Dump()
// returns a cumulative snapshot that the reporter diffs like conntrack.
type captureDumper struct {
	fd    int
	self4 netip.Addr
	self6 netip.Addr

	mu    sync.Mutex
	flows map[flowKey]*flowAccum

	closeOnce sync.Once
}

func newCaptureDumper(iface string, self4, self6 netip.Addr) (flowDumper, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("capture: interface %q: %w", iface, err)
	}

	// SOCK_DGRAM strips the link layer, so reads start at the IP header —
	// right for a WireGuard interface, which has no L2 header.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("capture: open packet socket: %w", err)
	}

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("capture: bind %q: %w", iface, err)
	}

	// A bigger receive buffer rides out short bursts without dropping.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)

	c := &captureDumper{
		fd:    fd,
		self4: self4.Unmap(),
		self6: self6.Unmap(),
		flows: make(map[flowKey]*flowAccum),
	}

	go c.run()

	return c, nil
}

func (c *captureDumper) run() {
	buf := make([]byte, captureSnapLen)

	for {
		// MSG_TRUNC returns the real packet length even though we only copy
		// header bytes — byte accounting stays exact, per-packet work stays
		// bounded.
		n, _, err := unix.Recvfrom(c.fd, buf, unix.MSG_TRUNC)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			// Close() shut the socket (EBADF), or a fatal error: stop.
			return
		}
		if n <= 0 {
			continue
		}

		end := n
		if end > len(buf) {
			end = len(buf)
		}
		c.account(buf[:end], n)
	}
}

func (c *captureDumper) account(pkt []byte, length int) {
	proto, src, sport, dst, dport, ok := parseFlowTuple(pkt)
	if !ok {
		return
	}

	var key flowKey
	var outbound bool
	switch {
	case c.isSelf(src):
		key = flowKey{protocol: proto, src: src, srcPort: sport, dst: dst, dstPort: dport}
		outbound = true
	case c.isSelf(dst):
		// Orient the local endpoint as src so a flow keeps one stable key
		// regardless of packet direction.
		key = flowKey{protocol: proto, src: dst, srcPort: dport, dst: src, dstPort: sport}
	default:
		return // neither end is us: not this host's overlay traffic
	}

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	a := c.flows[key]
	if a == nil {
		if len(c.flows) >= captureMaxFlows {
			c.evictLocked(now)
			if len(c.flows) >= captureMaxFlows {
				return // still full: drop this new flow rather than grow unbounded
			}
		}
		a = &flowAccum{}
		c.flows[key] = a
	}

	if outbound {
		a.txBytes += uint64(length)
		a.txPackets++
	} else {
		a.rxBytes += uint64(length)
		a.rxPackets++
	}
	a.lastSeen = now
}

func (c *captureDumper) isSelf(a netip.Addr) bool {
	return (c.self4.IsValid() && a == c.self4) || (c.self6.IsValid() && a == c.self6)
}

func (c *captureDumper) Dump() ([]ctFlow, error) {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictLocked(now)

	out := make([]ctFlow, 0, len(c.flows))
	for k, a := range c.flows {
		out = append(out, ctFlow{
			protocol:  k.protocol,
			src:       k.src,
			srcPort:   k.srcPort,
			dst:       k.dst,
			dstPort:   k.dstPort,
			txBytes:   a.txBytes,
			txPackets: a.txPackets,
			rxBytes:   a.rxBytes,
			rxPackets: a.rxPackets,
		})
	}

	return out, nil
}

func (c *captureDumper) evictLocked(now time.Time) {
	for k, a := range c.flows {
		if now.Sub(a.lastSeen) > captureFlowTTL {
			delete(c.flows, k)
		}
	}
}

func (c *captureDumper) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = unix.Close(c.fd) // unblocks run()'s Recvfrom with EBADF
	})
	return err
}

// parseFlowTuple extracts the 5-tuple from a network-layer packet (the
// payload of an AF_PACKET SOCK_DGRAM read — no link-layer header). It reads
// only header bytes and tolerates truncation past the L4 ports.
func parseFlowTuple(pkt []byte) (proto uint8, src netip.Addr, sport uint16, dst netip.Addr, dport uint16, ok bool) {
	if len(pkt) < 1 {
		return
	}

	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return
		}
		proto = pkt[9]
		src = netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
		dst = netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
		sport, dport = l4Ports(proto, pkt[ihl:])
		return proto, src, sport, dst, dport, true

	case 6:
		if len(pkt) < 40 {
			return
		}
		proto = pkt[6] // next header; extension headers are treated as "no ports"
		var s, d [16]byte
		copy(s[:], pkt[8:24])
		copy(d[:], pkt[24:40])
		src = netip.AddrFrom16(s)
		dst = netip.AddrFrom16(d)
		sport, dport = l4Ports(proto, pkt[40:])
		return proto, src, sport, dst, dport, true
	}

	return
}

func l4Ports(proto uint8, l4 []byte) (sport, dport uint16) {
	if (proto == unix.IPPROTO_TCP || proto == unix.IPPROTO_UDP) && len(l4) >= 4 {
		sport = binary.BigEndian.Uint16(l4[0:2])
		dport = binary.BigEndian.Uint16(l4[2:4])
	}
	return
}

// htons converts a uint16 to network byte order (the build targets are
// little-endian amd64/arm64).
func htons(v uint16) uint16 {
	return v<<8 | v>>8
}
