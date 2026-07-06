//go:build linux

package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgctrlBackend drives kernel WireGuard through wgctrl (netlink). The
// device already exists by the time the backend is created, so it only
// binds the interface name onto each call.
type wgctrlBackend struct {
	client *wgctrl.Client
	iface  string
}

func newWGBackend(iface string) (wgBackend, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("create wgctrl client: %w", err)
	}

	return &wgctrlBackend{client: client, iface: iface}, nil
}

func (b *wgctrlBackend) Device() (*wgtypes.Device, error) {
	return b.client.Device(b.iface)
}

func (b *wgctrlBackend) ConfigureDevice(cfg wgtypes.Config) error {
	return b.client.ConfigureDevice(b.iface, cfg)
}

func (b *wgctrlBackend) Close() error {
	return b.client.Close()
}
