package httpx

import (
	"math"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter is a per-client-IP token bucket for public endpoints.
// It caps how fast any single source can hit the control plane,
// limiting setup-key brute force, relay-pair exhaustion, and repeated
// WebSocket session opens.
type RateLimiter struct {
	rate    rate.Limit
	burst   int
	mu      sync.Mutex
	clients map[string]*clientLimiter
}

type clientLimiter struct {
	limiter *rate.Limiter
	last    time.Time
}

func NewRateLimiter(perSecond, burst float64) *RateLimiter {
	burstTokens := int(math.Ceil(burst))
	if burstTokens < 1 {
		burstTokens = 1
	}

	rl := &RateLimiter{
		rate:    rate.Limit(perSecond),
		burst:   burstTokens,
		clients: make(map[string]*clientLimiter),
	}

	go rl.evictLoop()

	return rl
}

// Allow consumes one token for key, refilling by elapsed time first.
func (rl *RateLimiter) Allow(key string) bool {
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

func (rl *RateLimiter) evictLoop() {
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

// Middleware rejects requests over the limit with 429, keyed on the
// client's real address.
func (rl *RateLimiter) Middleware(clientIP func(*http.Request) string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(clientIP(r)) {
			WriteError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		next(w, r)
	}
}
