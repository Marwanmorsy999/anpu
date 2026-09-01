package http

import (
	"context"
	"sync"
	"time"
)

// RateLimiter is a token-bucket rate limiter used to cap the total
// number of HTTP requests ANPU makes across all pipeline stages.
//
// It is safe for concurrent use.  When the rate is 0 (unlimited) all
// calls to Wait return immediately with no allocation overhead.
type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64       // max burst = capacity (1 request burst by default)
	rate     float64       // tokens added per second (0 = unlimited)
	last     time.Time     // last time tokens were refilled
	delay    time.Duration // fixed extra delay applied after every request
}

// NewRateLimiter constructs a RateLimiter.
//   - rps: max requests per second (0 = unlimited)
//   - delay: fixed inter-request sleep added after every request (0 = none)
func NewRateLimiter(rps float64, delay time.Duration) *RateLimiter {
	rl := &RateLimiter{
		rate:  rps,
		delay: delay,
		last:  time.Now(),
	}
	if rps > 0 {
		rl.capacity = rps // burst equals one second's worth of requests
		rl.tokens = rps   // start full
	}
	return rl
}

// Wait blocks until a token is available (respecting rps cap) and then
// sleeps for the configured fixed delay.  It returns ctx.Err() if the
// context is cancelled while waiting.
func (rl *RateLimiter) Wait(ctx context.Context) error {
	if rl.rate > 0 {
		if err := rl.acquireToken(ctx); err != nil {
			return err
		}
	}
	if rl.delay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(rl.delay):
		}
	}
	return nil
}

// acquireToken blocks until one token is available in the bucket.
func (rl *RateLimiter) acquireToken(ctx context.Context) error {
	for {
		rl.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(rl.last).Seconds()
		rl.tokens += elapsed * rl.rate
		if rl.tokens > rl.capacity {
			rl.tokens = rl.capacity
		}
		rl.last = now

		if rl.tokens >= 1.0 {
			rl.tokens--
			rl.mu.Unlock()
			return nil
		}

		// Calculate how long until the next token is available.
		wait := time.Duration((1.0-rl.tokens)/rl.rate*1000) * time.Millisecond
		rl.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// nopLimiter is returned when rate limiting is disabled.
type nopLimiter struct{}

func (nopLimiter) Wait(_ context.Context) error { return nil }
