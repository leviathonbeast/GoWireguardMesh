//go:build windows

package main

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/Microsoft/go-winio"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Windows has no kernel WireGuard we can drive over netlink, so the
// agent embeds wireguard-go as a library: it creates a Wintun
// adapter in-process, runs the userspace WireGuard device, and
// exposes the standard UAPI named pipe — which is exactly what wgctrl
// speaks on Windows, so everything else (configure, telemetry, sync)
// works unchanged.
//
// Runtime requirements: wintun.dll next to agent.exe (download from
// https://www.wintun.net) and an elevated (Administrator) prompt.

var (
	wgDevice     *device.Device
	uapiListener net.Listener
)

// uapiListen opens the pipe wgctrl expects for this adapter name.
// wireguard-go's own ipc.UAPIListen hardcodes the pipe owner to
// LocalSystem (O:SY), which only works when running as the SYSTEM
// service the official client installs. We run from an elevated
// prompt, whose token owns the Administrators group instead — so we
// create the identical pipe with owner BA. Same path, same ACL
// (full access for SYSTEM and Administrators only).
func uapiListen(name string) (net.Listener, error) {
	return winio.ListenPipe(
		`\\.\pipe\ProtectedPrefix\Administrators\WireGuard\`+name,
		&winio.PipeConfig{SecurityDescriptor: "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"},
	)
}

func ensurePrivileged() error {
	// No euid on Windows; Wintun adapter creation fails without
	// elevation, which produces a clearer error than any preflight.
	return nil
}

func createInterface(name string) error {
	tunDev, err := tun.CreateTUN(name, device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("create wintun adapter %q (is wintun.dll next to agent.exe, and is this prompt elevated?): %w", name, err)
	}

	dev := device.NewDevice(
		tunDev,
		conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", name)),
	)

	uapi, err := uapiListen(name)
	if err != nil {
		dev.Close()
		return fmt.Errorf("listen on UAPI pipe for %q: %w", name, err)
	}

	go func() {
		for {
			c, err := uapi.Accept()
			if err != nil {
				return // listener closed during teardown
			}

			go dev.IpcHandle(c)
		}
	}()

	wgDevice = dev
	uapiListener = uapi

	fmt.Printf("Created interface %s (userspace wireguard-go, wintun)\n", name)

	return nil
}

func assignIPAddress(ifaceName, cidr string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	mask := net.IP(ipnet.Mask).String()

	out, err := exec.Command("netsh", "interface", "ipv4", "set", "address",
		"name="+ifaceName, "static", ip.String(), mask).CombinedOutput()
	if err != nil {
		return fmt.Errorf("assign address %q via netsh: %w: %s", cidr, err, out)
	}

	fmt.Printf("Assigned %s to %s\n", cidr, ifaceName)

	return nil
}

func bringInterfaceUp(ifaceName string) error {
	// Wintun adapters are up once created; nothing to do.
	return nil
}

func deleteInterface(ifaceName string) error {
	if uapiListener != nil {
		uapiListener.Close()
		uapiListener = nil
	}

	if wgDevice != nil {
		wgDevice.Close()
		wgDevice = nil

		fmt.Printf("Deleted interface %s\n", ifaceName)
	}

	return nil
}
