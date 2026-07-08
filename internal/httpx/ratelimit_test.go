package httpx

import "testing"

func TestRateLimiterUsesPerClientBurst(t *testing.T) {
	rl := NewRateLimiter(1, 2)

	if !rl.Allow("192.0.2.10") {
		t.Fatal("first request should be allowed")
	}
	if !rl.Allow("192.0.2.10") {
		t.Fatal("second request should be allowed by burst")
	}
	if rl.Allow("192.0.2.10") {
		t.Fatal("third immediate request should be rate limited")
	}
	if !rl.Allow("192.0.2.11") {
		t.Fatal("different client should have its own limiter")
	}
}
