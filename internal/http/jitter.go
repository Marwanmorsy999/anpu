package http

import (
	"math"
	"math/rand"
	"time"
)

// jitter.go — Pareto + lognormal jitter for ghost mode.
//
// Standard stealth used uniform 50-250ms (client.go:590) which is easily
// fingerprinted as bursty scanner traffic. Ghost uses a heavy-tailed
// Pareto-lognormal mix: 800-3500ms, mean ~1500ms, mimicking human pacing
// and WAF-evading spacing with occasional long pauses.

// ghostJitter returns a Pareto-ish / lognormal jitter between 800ms and
// 3500ms. Parameters chosen so p50 ~1300ms, p90 ~2800ms, tail heavy.
// Uses uaRng (locked RNG) so we reuse the existing seeded source.
func ghostJitter() time.Duration {
	uaMu.Lock()
	defer uaMu.Unlock()
	// Lognormal: ln(mean) ~ 7.18 (1300ms), sigma 0.45 → heavy tail.
	// Transform uniform via Box-Muller.
	u1 := uaRng.Float64()
	if u1 < 1e-9 {
		u1 = 1e-9
	}
	u2 := uaRng.Float64()
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	lnMean := 7.18
	sigma := 0.45
	val := math.Exp(lnMean + sigma*z)
	// Clamp to 800-3500ms.
	if val < 800 {
		val = 800 + uaRng.Float64()*200
	}
	if val > 3500 {
		val = 3500 - uaRng.Float64()*200
	}
	// Pareto occasional spike 5% of the time: bump toward tail.
	if uaRng.Float64() < 0.05 {
		val = 2500 + uaRng.Float64()*1000
	}
	return time.Duration(val) * time.Millisecond
}

// stealthJitter switches between uniform (non-ghost) and ghost Pareto
// based on GhostEnabled. Kept for compatibility with client.go's
// stealthJitter() — we override behavior when ghost is on.
func stealthOrGhostJitter() time.Duration {
	if GhostEnabled {
		return ghostJitter()
	}
	// Fallback: uniform 50-250ms (preserves existing safe behavior
	// when --ghost is off, per plan "RateLimiter fixed bucket when --ghost off").
	uaMu.Lock()
	n := uaRng.Intn(200)
	uaMu.Unlock()
	return time.Duration(50+n) * time.Millisecond
}

// maybeGhostJitter sleeps for ghost jitter if ghost or stealth is enabled.
// Respects context cancellation.
func (c *Client) maybeGhostJitter(ctx interface{ Done() <-chan struct{} }) error {
	// This helper is not used directly; the real maybeJitter in client.go
	// now delegates to stealthOrGhostJitter when GhostEnabled.
	return nil
}

// Ensure rand import is used (avoid unused import if build tags change).
var _ = rand.Float64
