// Package psk manages the mesh's network-wide WireGuard preshared key.
//
// This is deliberately one secret for the whole network, not one per
// peer-pair: the peers table has no pairwise join table, and a single
// value is trivially symmetric (every peer's config entry for every
// other peer carries the same PSK). True per-pair secrecy would need
// an O(n^2) key table this project doesn't have.
package psk

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LoadOrGenerate loads the network preshared key from path, generating
// and persisting a new one (0600) if the file does not exist.
func LoadOrGenerate(path string) (wgtypes.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			key, err := wgtypes.GenerateKey()
			if err != nil {
				return wgtypes.Key{}, fmt.Errorf("generate preshared key: %w", err)
			}

			if err := os.WriteFile(path, []byte(key.String()+"\n"), 0600); err != nil {
				return wgtypes.Key{}, fmt.Errorf("write preshared key file %q: %w", path, err)
			}

			return key, nil
		}

		return wgtypes.Key{}, fmt.Errorf("read preshared key file %q: %w", path, err)
	}

	key, err := wgtypes.ParseKey(strings.TrimSpace(string(data)))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("parse preshared key file %q: %w", path, err)
	}

	return key, nil
}
