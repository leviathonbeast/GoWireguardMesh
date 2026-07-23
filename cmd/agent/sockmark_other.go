//go:build !linux

package main

import (
	"context"
	"net"
)

// SO_MARK is Linux-only; other platforms have no exit-node policy
// routing to bypass, so plain sockets are correct.

func markedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func listenUDPMarked(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	return net.ListenUDP(network, laddr)
}
