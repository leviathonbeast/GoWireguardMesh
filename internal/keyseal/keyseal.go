// Package keyseal encrypts the secrets the control plane must be able to
// reproduce later — today, the private keys of static WireGuard peers,
// so their configs can be shown again from the admin UI.
//
// The ciphertext lives in the SQLite database. The key that opens it is
// derived from the mesh PSK master, which lives in a separate file that
// never goes on the wire. A stolen mesh.db — a backup, a snapshot, a
// stray scp — is inert without that file.
//
// This is not a substitute for not storing the key at all. An attacker
// with both the database and the master file recovers every device key,
// exactly as they already recover every pair PSK.
package keyseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// deviceKeyInfo separates this subkey from the per-pair PSKs derived
// from the same master. Changing it invalidates every stored secret.
const deviceKeyInfo = "wgmesh-device-key:v1"

// ErrCorrupt reports a sealed value that does not authenticate: a wrong
// master key, a truncated column, or a ciphertext moved between rows.
var ErrCorrupt = errors.New("sealed value failed authentication")

// Sealer encrypts and decrypts secrets at rest. It is safe for
// concurrent use: cipher.AEAD is stateless.
type Sealer struct {
	aead cipher.AEAD
}

// New derives the sealing subkey from the mesh PSK master.
func New(master wgtypes.Key) (*Sealer, error) {
	subkey, err := hkdf.Key(sha256.New, master[:], nil, deviceKeyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive device-key subkey: %w", err)
	}

	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, fmt.Errorf("device-key cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("device-key aead: %w", err)
	}

	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext and returns it base64-encoded, ready for a TEXT
// column. binding is authenticated but not encrypted: pass a value that
// pins the ciphertext to its row — a peer's public key — so that moving
// the column to another peer fails to open rather than silently handing
// that peer someone else's private key.
func (s *Sealer) Seal(binding, plaintext string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	sealed := s.aead.Seal(nonce, nonce, []byte(plaintext), []byte(binding))

	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal. binding must match the value given to Seal.
func (s *Sealer) Open(binding, sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if len(raw) < s.aead.NonceSize() {
		return "", fmt.Errorf("%w: short ciphertext", ErrCorrupt)
	}

	nonce, ciphertext := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, []byte(binding))
	if err != nil {
		return "", ErrCorrupt
	}

	return string(plaintext), nil
}
