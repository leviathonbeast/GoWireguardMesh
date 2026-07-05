package psk

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	xhkdf "golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// xCryptoDerive is the pre-Go-1.24 derivation this package used
// (golang.org/x/crypto/hkdf). It is kept in tests as the compatibility
// oracle: DerivePairKey moved to the standard library's crypto/hkdf,
// and a mesh in the field must keep deriving byte-identical PSKs or
// every pair would churn on upgrade.
func xCryptoDerive(t *testing.T, master wgtypes.Key, pubA, pubB string) wgtypes.Key {
	t.Helper()

	lo, hi := pubA, pubB
	if lo > hi {
		lo, hi = hi, lo
	}

	r := xhkdf.New(sha256.New, master[:], nil, []byte("wgmesh-pair-psk:"+lo+"|"+hi))

	var key wgtypes.Key
	if _, err := io.ReadFull(r, key[:]); err != nil {
		t.Fatalf("x/crypto hkdf read: %v", err)
	}

	return key
}

// TestDerivePairKeyPinnedVector pins one derivation to a literal
// computed with the original x/crypto implementation. If BOTH
// implementations ever drift (or someone edits the info string), this
// catches it where the cross-check below cannot.
func TestDerivePairKeyPinnedVector(t *testing.T) {
	var master wgtypes.Key
	for i := range master {
		master[i] = byte(i)
	}

	got, err := DerivePairKey(master,
		"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
		"YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
	)
	if err != nil {
		t.Fatalf("DerivePairKey: %v", err)
	}

	const want = "Rh9gi8ay+sdxD5WAlvkV8bf2lhUdJzaoC0v2TzmXjCY="
	if got.String() != want {
		t.Fatalf("DerivePairKey pinned vector = %s, want %s", got, want)
	}
}

// TestDerivePairKeyMatchesXCryptoHKDF cross-checks the stdlib
// derivation against the x/crypto oracle over random inputs.
func TestDerivePairKeyMatchesXCryptoHKDF(t *testing.T) {
	for i := 0; i < 32; i++ {
		var master wgtypes.Key
		if _, err := rand.Read(master[:]); err != nil {
			t.Fatalf("rand master: %v", err)
		}

		a, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		b, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}

		pubA, pubB := a.PublicKey().String(), b.PublicKey().String()

		got, err := DerivePairKey(master, pubA, pubB)
		if err != nil {
			t.Fatalf("DerivePairKey: %v", err)
		}

		if want := xCryptoDerive(t, master, pubA, pubB); got != want {
			t.Fatalf("iteration %d: stdlib %s != x/crypto %s", i, got, want)
		}
	}
}

// TestDerivePairKeyInvariants: argument order must not matter, and
// distinct pairs must not collide.
func TestDerivePairKeyInvariants(t *testing.T) {
	var master wgtypes.Key
	if _, err := rand.Read(master[:]); err != nil {
		t.Fatalf("rand master: %v", err)
	}

	keys := make([]string, 3)
	for i := range keys {
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		keys[i] = k.PublicKey().String()
	}

	ab, err := DerivePairKey(master, keys[0], keys[1])
	if err != nil {
		t.Fatalf("DerivePairKey: %v", err)
	}
	ba, err := DerivePairKey(master, keys[1], keys[0])
	if err != nil {
		t.Fatalf("DerivePairKey: %v", err)
	}
	if ab != ba {
		t.Fatal("DerivePairKey is order-dependent")
	}

	ac, err := DerivePairKey(master, keys[0], keys[2])
	if err != nil {
		t.Fatalf("DerivePairKey: %v", err)
	}
	if ab == ac {
		t.Fatal("distinct pairs derived the same PSK")
	}
}
