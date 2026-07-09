package keyseal

import (
	"errors"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testSealer(t *testing.T) (*Sealer, wgtypes.Key) {
	t.Helper()

	master, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate master: %v", err)
	}
	s, err := New(master)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return s, master
}

func TestSealOpenRoundTrip(t *testing.T) {
	s, _ := testSealer(t)

	device, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	want := device.String()
	binding := device.PublicKey().String()

	sealed, err := s.Seal(binding, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(sealed, want) {
		t.Fatal("sealed value leaks the plaintext private key")
	}

	got, err := s.Open(binding, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != want {
		t.Fatalf("Open = %q, want %q", got, want)
	}
}

// Each Seal must use a fresh nonce: GCM catastrophically leaks on reuse.
func TestSealIsRandomized(t *testing.T) {
	s, _ := testSealer(t)

	first, err := s.Seal("peer", "secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := s.Seal("peer", "secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if first == second {
		t.Fatal("sealing the same plaintext twice produced identical ciphertext")
	}
}

// The binding pins a ciphertext to its row, so a private key column copied
// onto another peer must not open.
func TestOpenRejectsWrongBinding(t *testing.T) {
	s, _ := testSealer(t)

	sealed, err := s.Seal("peer-a-public-key", "secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := s.Open("peer-b-public-key", sealed); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open with wrong binding: err = %v, want ErrCorrupt", err)
	}
}

func TestOpenRejectsWrongMaster(t *testing.T) {
	s, _ := testSealer(t)
	other, _ := testSealer(t)

	sealed, err := s.Seal("peer", "secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := other.Open("peer", sealed); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open under a different master: err = %v, want ErrCorrupt", err)
	}
}

func TestOpenRejectsTamperedAndMalformed(t *testing.T) {
	s, _ := testSealer(t)

	sealed, err := s.Seal("peer", "secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	flipped := []byte(sealed)
	flipped[len(flipped)-2] ^= 'A' ^ 'B'

	cases := map[string]string{
		"tampered":   string(flipped),
		"not base64": "!!!not-base64!!!",
		"truncated":  sealed[:4],
		"empty":      "",
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Open("peer", input); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Open(%s): err = %v, want ErrCorrupt", name, err)
			}
		})
	}
}

// A Sealer derived from the same master must open what an earlier process
// sealed: the subkey derivation has to be deterministic across restarts.
func TestSealerIsDeterministicAcrossInstances(t *testing.T) {
	s, master := testSealer(t)

	sealed, err := s.Seal("peer", "secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	restarted, err := New(master)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := restarted.Open("peer", sealed)
	if err != nil {
		t.Fatalf("Open after restart: %v", err)
	}
	if got != "secret" {
		t.Fatalf("Open after restart = %q, want %q", got, "secret")
	}
}
