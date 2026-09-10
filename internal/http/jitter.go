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

// Ensure rand import is used (avoid unused import if build tags change).
var _ = rand.Float64
