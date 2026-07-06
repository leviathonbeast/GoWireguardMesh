//go:build windows

package main

import (
	"errors"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// embeddedBackend drives the in-process wireguard-go device (wgDevice,
// created in iface_windows.go) through its UAPI. Windows has no kernel
// WireGuard and no wgctrl named pipe, so telemetry, sync, and relay
// fallback all read/write the device directly with IpcGet/IpcSet.
type embeddedBackend struct{}

func newWGBackend(iface string) (wgBackend, error) {
	if wgDevice == nil {
		return nil, errors.New("embedded wireguard device not initialized")
	}

	return &embeddedBackend{}, nil
}

func (b *embeddedBackend) Device() (*wgtypes.Device, error) {
	if wgDevice == nil {
		return nil, errors.New("embedded wireguard device not initialized")
	}

	conf, err := wgDevice.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("ipc get: %w", err)
	}

	return parseUAPI(conf)
}

func (b *embeddedBackend) ConfigureDevice(cfg wgtypes.Config) error {
	if wgDevice == nil {
		return errors.New("embedded wireguard device not initialized")
	}

	if err := wgDevice.IpcSet(buildIPCSet(cfg)); err != nil {
		return fmt.Errorf("ipc set: %w", err)
	}

	return nil
}

func (b *embeddedBackend) Close() error { return nil }
