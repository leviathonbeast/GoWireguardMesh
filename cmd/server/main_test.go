package main

import "testing"

func TestOverlayAddressUsesHostPrefix(t *testing.T) {
	got, err := overlayAddress("100.64.0.7")
	if err != nil {
		t.Fatalf("overlayAddress returned error: %v", err)
	}

	want := "100.64.0.7/32"
	if got != want {
		t.Fatalf("overlayAddress() = %q, want %q", got, want)
	}
}
