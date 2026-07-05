//go:build windows

package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func configureWireGuard(
	iface string,
	privateKey wgtypes.Key,
	listenPort int,
	peers []wgtypes.PeerConfig,
) error {
	return configureWireGuardWindows(
		privateKey,
		listenPort,
		peers,
	)
}

func printDeviceState(iface string) error {
	fmt.Println("\n===== Embedded WireGuard Device =====")
	fmt.Printf("Name        : %s\n", iface)
	fmt.Printf("Listen Port : %d\n", listenPortFlag)

	return nil
}
