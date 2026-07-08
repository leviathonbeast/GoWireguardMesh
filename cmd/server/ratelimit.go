package main

import (
	"math"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimiter is a per-client-IP token bucket guarding the public
// endpoints (enroll, report, relay). It caps how fast any single
// source can hit the control plane — brute-forcing setup keys,
// exhausting relay pairs, or opening relay sessions in a loop. A
// public VPS control plane needs this; a LAN one benefits from it.
type rateLimiter struct {
	rate    rate.Limit
	burst   int
	mu      sync.Mutex
	clients map[string]*clientLimiter
}

type clientLimiter struct {
	limiter *rate.Limiter
	last    time.Time
}

func newRateLimiter(perSecond, burst float64) *rateLimiter {
	burstTokens := int(math.Ceil(burst))
	if burstTokens < 1 {
		burstTokens = 1
	}

	rl := &rateLimiter{
		rate:    rate.Limit(perSecond),
		burst:   burstTokens,
		clients: make(map[string]*clientLimiter),
	}

	go rl.evictLoop()

	return rl
}

// allow consumes one token for key, refilling by elapsed time first.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	now := time.Now()

	c := rl.clients[key]
	if c == nil {
		c = &clientLimiter{
			limiter: rate.NewLimiter(rl.rate, rl.burst),
			last:    now,
		}
		rl.clients[key] = c
	} else {
		c.last = now
	}
	limiter := c.limiter
	rl.mu.Unlock()

	return limiter.Allow()
}

// evictLoop drops idle buckets so the map does not grow without bound
// under changing source addresses.
func (rl *rateLimiter) evictLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()

		for key, c := range rl.clients {
			if time.Since(c.last) > 10*time.Minute {
				delete(rl.clients, key)
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
