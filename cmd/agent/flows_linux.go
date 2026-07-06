//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"github.com/ti-mo/conntrack"
)

const conntrackAcctPath = "/proc/sys/net/netfilter/nf_conntrack_acct"

// conntrackDumper adapts ti-mo/conntrack to the flowDumper interface.
type conntrackDumper struct {
	conn *conntrack.Conn
}

// newFlowDumper picks a flow source. conntrack is preferred when byte
// accounting is available — it is cheap, the kernel already tracks the
// connections. When accounting is off and cannot be enabled (a read-only
// /proc/sys, i.e. inside a container) it falls back to capturing the
// overlay interface, which needs no sysctl — just CAP_NET_RAW.
func newFlowDumper(iface string, self4, self6 netip.Addr) (flowDumper, error) {
	if conntrackAcctReady() {
		if d, err := newConntrackDumper(); err == nil {
			return d, nil
		} else {
			slog.Warn("conntrack flow source failed; capturing overlay instead", "error", err)
		}
	} else {
		slog.Info("conntrack byte accounting unavailable; capturing overlay for flow logs", "iface", iface)
	}

	return newCaptureDumper(iface, self4, self6)
}

// conntrackAcctReady reports whether conntrack byte accounting is on, or
// could be turned on here. It is a host-global knob, so an already-enabled
// value (e.g. set on the Docker host) is used as-is; otherwise we try to
// enable it. A failed write — a read-only /proc/sys inside a container — is
// the signal to fall back to capture.
func conntrackAcctReady() bool {
	if conntrackAcctEnabled() {
		return true
	}

	return os.WriteFile(conntrackAcctPath, []byte("1\n"), 0644) == nil
}

// conntrackAcctEnabled reports whether conntrack byte/packet accounting is
// already on.
func conntrackAcctEnabled() bool {
	b, err := os.ReadFile(conntrackAcctPath)
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(b)) == "1"
}

func newConntrackDumper() (flowDumper, error) {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("conntrack unavailable (%v)", err)
	}

	return &conntrackDumper{conn: conn}, nil
}

func (d *conntrackDumper) Dump() ([]ctFlow, error) {
	flows, err := d.conn.Dump(nil)
	if err != nil {
		return nil, err
	}

	out := make([]ctFlow, 0, len(flows))

	for _, f := range flows {
		out = append(out, ctFlow{
			protocol:  f.TupleOrig.Proto.Protocol,
			src:       f.TupleOrig.IP.SourceAddress,
			dst:       f.TupleOrig.IP.DestinationAddress,
			srcPort:   f.TupleOrig.Proto.SourcePort,
			dstPort:   f.TupleOrig.Proto.DestinationPort,
			txBytes:   f.CountersOrig.Bytes,
			txPackets: f.CountersOrig.Packets,
			rxBytes:   f.CountersReply.Bytes,
			rxPackets: f.CountersReply.Packets,
		})
	}

	return out, nil
}

func (d *conntrackDumper) Close() error {
	return d.conn.Close()
}
