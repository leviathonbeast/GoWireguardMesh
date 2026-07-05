//go:build linux

package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func configureWireGuard(
	iface string,
	privateKey wgtypes.Key,
	listenPort int,
	peers []wgtypes.PeerConfig,
) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf(
			"create wgctrl client: %w",
			err,
		)
	}
	defer client.Close()

	cfg := wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers:        peers,
	}

	if err := client.ConfigureDevice(iface, cfg); err != nil {
		return fmt.Errorf(
			"configure device %q: %w",
			iface,
			err,
		)
	}

	fmt.Println("Configured WireGuard device")

	return nil
}

func printDeviceState(iface string) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf(
			"create wgctrl client: %w",
			err,
		)
	}
	defer client.Close()

	device, err := client.Device(iface)
	if err != nil {
		return fmt.Errorf(
			"read device %q: %w",
			iface,
			err,
		)
	}

	fmt.Println("\n===== WireGuard Device =====")
	fmt.Printf("Name        : %s\n", device.Name)
	fmt.Printf("Public Key  : %s\n", device.PublicKey)
	fmt.Printf("Listen Port : %d\n", device.ListenPort)
	fmt.Printf("Peers       : %d\n", len(device.Peers))

	return nil
}
