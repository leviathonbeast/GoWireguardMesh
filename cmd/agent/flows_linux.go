//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ti-mo/conntrack"
)

const conntrackAcctPath = "/proc/sys/net/netfilter/nf_conntrack_acct"

// conntrackDumper adapts ti-mo/conntrack to the flowDumper interface.
type conntrackDumper struct {
	conn *conntrack.Conn
}

func newFlowDumper() (flowDumper, error) {
	// Flow visibility needs conntrack byte/packet accounting, which is off
	// by default on most kernels. It is a host-global knob, so if it is
	// already on (e.g. enabled on the Docker host) we use it as-is —
	// containers mount /proc/sys read-only and cannot write it themselves.
	if !conntrackAcctEnabled() {
		if err := os.WriteFile(conntrackAcctPath, []byte("1\n"), 0644); err != nil {
			return nil, fmt.Errorf("conntrack accounting is off and could not be enabled (%v); "+
				"for flow logs in a container, enable it on the host: sysctl -w net.netfilter.nf_conntrack_acct=1", err)
		}
	}

	conn, err := conntrack.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("conntrack unavailable (%v)", err)
	}

	return &conntrackDumper{conn: conn}, nil
}

// conntrackAcctEnabled reports whether conntrack byte/packet accounting is
// already on, letting us skip the sysctl write that a read-only /proc/sys
// (the container default) would reject.
func conntrackAcctEnabled() bool {
	b, err := os.ReadFile(conntrackAcctPath)
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(b)) == "1"
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
