//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/ti-mo/conntrack"
)

// conntrackDumper adapts ti-mo/conntrack to the flowDumper interface.
type conntrackDumper struct {
	conn *conntrack.Conn
}

func newFlowDumper() (flowDumper, error) {
	// Flow visibility needs conntrack byte/packet accounting, which is
	// off by default on most kernels.
	if err := os.WriteFile("/proc/sys/net/netfilter/nf_conntrack_acct", []byte("1\n"), 0644); err != nil {
		return nil, fmt.Errorf("cannot enable conntrack accounting (%v)", err)
	}

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
