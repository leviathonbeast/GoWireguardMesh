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
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DerivePairKey computes the preshared key for the (pubA, pubB) pair.
// Argument order does not matter.
//
// Uses the standard library's crypto/hkdf (Go 1.24+); the derivation
// is RFC 5869 HKDF-SHA256 and byte-identical to the previous
// golang.org/x/crypto/hkdf implementation, so existing meshes keep
// their PSKs (pinned by TestDerivePairKeyMatchesXCryptoHKDF).
func DerivePairKey(master wgtypes.Key, pubA, pubB string) (wgtypes.Key, error) {
	lo, hi := pubA, pubB
	if lo > hi {
		lo, hi = hi, lo
	}

	raw, err := hkdf.Key(sha256.New, master[:], nil, "wgmesh-pair-psk:"+lo+"|"+hi, len(wgtypes.Key{}))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("derive pair psk: %w", err)
	}

	var key wgtypes.Key
	copy(key[:], raw)

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
