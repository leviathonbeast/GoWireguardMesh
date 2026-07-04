// Package psk manages WireGuard preshared keys for the mesh.
//
// The file on disk is a MASTER secret that never goes on the wire.
// Each peer pair's actual PSK is derived from it with HKDF keyed on
// the pair's sorted public keys: symmetric by construction (both
// sides compute the same value server-side), unique per pair, and
// requiring no O(n^2) key storage. Compromising one pair's PSK
// reveals nothing about any other pair's.
package psk

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DerivePairKey computes the preshared key for the (pubA, pubB) pair.
// Argument order does not matter.
func DerivePairKey(master wgtypes.Key, pubA, pubB string) (wgtypes.Key, error) {
	lo, hi := pubA, pubB
	if lo > hi {
		lo, hi = hi, lo
	}

	r := hkdf.New(sha256.New, master[:], nil, []byte("wgmesh-pair-psk:"+lo+"|"+hi))

	var key wgtypes.Key
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return wgtypes.Key{}, fmt.Errorf("derive pair psk: %w", err)
	}

	return key, nil
}

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
