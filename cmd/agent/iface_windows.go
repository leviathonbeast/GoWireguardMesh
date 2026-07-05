//go:build windows

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Windows has no kernel WireGuard netlink interface.
// Instead, we embed wireguard-go directly in-process using Wintun.
//
// This means:
//
//   - tun.CreateTUN() creates the Wintun adapter
//   - device.NewDevice() runs the WireGuard backend
//   - wgDevice.IpcSet() configures peers directly
//
// We do NOT use wgctrl/UAPI on Windows because there is no
// external WireGuard kernel backend to control.
//
// Runtime requirements:
//
//   - wintun.dll next to agent.exe
//   - elevated Administrator prompt

var (
	wgDevice *device.Device
)

func ensurePrivileged() error {
	// No euid on Windows; Wintun creation itself will fail
	// with a useful error if not elevated.
	return nil
}

func createInterface(name string) error {
	tunDev, err := tun.CreateTUN(name, device.DefaultMTU)
	if err != nil {
		return fmt.Errorf(
			"create wintun adapter %q (is wintun.dll next to agent.exe, and is this prompt elevated?): %w",
			name,
			err,
		)
	}

	dev := device.NewDevice(
		tunDev,
		conn.NewDefaultBind(),
		device.NewLogger(
			device.LogLevelError,
			fmt.Sprintf("(%s) ", name),
		),
	)

	// Bring the embedded WireGuard backend online.
	if err := dev.Up(); err != nil {
		dev.Close()

		return fmt.Errorf(
			"bring WireGuard device %q up: %w",
			name,
			err,
		)
	}

	wgDevice = dev

	fmt.Printf(
		"Created interface %s (userspace wireguard-go, wintun)\n",
		name,
	)

	return nil
}

func assignIPAddress(ifaceName, cidr string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	if ip.To4() == nil {
		ones, _ := ipnet.Mask.Size()
		out, err := exec.Command(
			"netsh",
			"interface",
			"ipv6",
			"add",
			"address",
			"interface="+ifaceName,
			fmt.Sprintf("%s/%d", ip.String(), ones),
		).CombinedOutput()

		if err != nil {
			return fmt.Errorf(
				"assign address %q via netsh: %w: %s",
				cidr,
				err,
				out,
			)
		}

		fmt.Printf("Assigned %s to %s\n", cidr, ifaceName)

		return nil
	}

	mask := net.IP(ipnet.Mask).String()

	out, err := exec.Command(
		"netsh",
		"interface",
		"ipv4",
		"set",
		"address",
		"name="+ifaceName,
		"static",
		ip.String(),
		mask,
	).CombinedOutput()

	if err != nil {
		return fmt.Errorf(
			"assign address %q via netsh: %w: %s",
			cidr,
			err,
			out,
		)
	}

	fmt.Printf("Assigned %s to %s\n", cidr, ifaceName)

	return nil
}

func bringInterfaceUp(ifaceName string) error {
	// Wintun adapters are already up once created.
	return nil
}

func deleteInterface(ifaceName string) error {
	if wgDevice != nil {
		wgDevice.Close()
		wgDevice = nil

		fmt.Printf("Deleted interface %s\n", ifaceName)
	}

	return nil
}

func buildIPCConfig(
	privateKey wgtypes.Key,
	listenPort int,
	peers []wgtypes.PeerConfig,
) string {
	var b strings.Builder

	fmt.Fprintf(
		&b,
		"private_key=%s\n",
		hex.EncodeToString(privateKey[:]),
	)

	fmt.Fprintf(
		&b,
		"listen_port=%d\n",
		listenPort,
	)

	for _, p := range peers {
		fmt.Fprintf(
			&b,
			"public_key=%s\n",
			hex.EncodeToString(p.PublicKey[:]),
		)

		if p.Endpoint != nil {
			fmt.Fprintf(
				&b,
				"endpoint=%s\n",
				p.Endpoint.String(),
			)
		}

		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(
				&b,
				"allowed_ip=%s\n",
				ip.String(),
			)
		}

		if p.PersistentKeepaliveInterval != nil {
			fmt.Fprintf(
				&b,
				"persistent_keepalive_interval=%d\n",
				int(p.PersistentKeepaliveInterval.Seconds()),
			)
		}

		fmt.Fprintf(&b, "\n")
	}

	return b.String()
}

func configureWireGuardWindows(
	privateKey wgtypes.Key,
	listenPort int,
	peers []wgtypes.PeerConfig,
) error {
	if wgDevice == nil {
		return fmt.Errorf("wireguard device not initialized")
	}

	cfg := buildIPCConfig(
		privateKey,
		listenPort,
		peers,
	)

	if err := wgDevice.IpcSet(cfg); err != nil {
		return fmt.Errorf(
			"configure embedded wireguard-go device: %w",
			err,
		)
	}

	fmt.Println("Configured embedded WireGuard device")

	return nil
}
