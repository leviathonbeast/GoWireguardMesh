//go:build !linux && !windows

package main

import "gowireguard/internal/proto"

func applyDNSConfig(_ string, _ proto.DNSConfig) error {
	return nil
}
