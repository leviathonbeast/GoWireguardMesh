package main

import (
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a per-client-IP token bucket guarding the public
// endpoints (enroll, report, relay). It caps how fast any single
// source can hit the control plane — brute-forcing setup keys,
// exhausting relay pairs, or opening relay sessions in a loop. A
// public VPS control plane needs this; a LAN one benefits from it.
type rateLimiter struct {
	rate   float64 // tokens added per second
	burst  float64 // bucket capacity
	mu     sync.Mutex
	tokens map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perSecond, burst float64) *rateLimiter {
	rl := &rateLimiter{
		rate:   perSecond,
		burst:  burst,
		tokens: make(map[string]*bucket),
	}

	go rl.evictLoop()

	return rl
}

// allow consumes one token for key, refilling by elapsed time first.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	b := rl.tokens[key]
	if b == nil {
		// A fresh client starts with a full bucket minus this request.
		rl.tokens[key] = &bucket{tokens: rl.burst - 1, last: now}
		return true
	}

	b.tokens += now.Sub(b.last).Seconds() * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}

	b.last = now

	if b.tokens < 1 {
		return false
	}

	b.tokens--

	return true
}

// evictLoop drops idle buckets so the map does not grow without bound
// under changing source addresses.
func (rl *rateLimiter) evictLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()

		for key, b := range rl.tokens {
			if time.Since(b.last) > 10*time.Minute {
				delete(rl.tokens, key)
			}
		}

		rl.mu.Unlock()
	}
}

// middleware rejects requests over the limit with 429, keyed on the
// client's real address (honouring the trust-proxy setting).
func (rl *rateLimiter) middleware(clientIP func(*http.Request) string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r)) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		next(w, r)
	}
}
