package main

import (
	"fmt"
	"net"
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

	serverAddr, err := net.ResolveUDPAddr("udp4", stunServer)
	if err != nil {
		return "", fmt.Errorf("resolve STUN server %q: %w", stunServer, err)
	}

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", fmt.Errorf("set STUN deadline: %w", err)
	}

	if _, err := conn.WriteTo(msg.Raw, serverAddr); err != nil {
		return "", fmt.Errorf("send STUN request to %q: %w", stunServer, err)
	}

	buf := make([]byte, 1500)

	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return "", fmt.Errorf("read STUN response from %q: %w", stunServer, err)
	}

	res := &stun.Message{Raw: buf[:n]}
	if err := res.Decode(); err != nil {
		return "", fmt.Errorf("decode STUN response: %w", err)
	}

	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(res); err != nil {
		return "", fmt.Errorf("no mapped address in STUN response: %w", err)
	}

	return mapped.String(), nil
}
