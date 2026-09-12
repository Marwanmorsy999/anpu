package main

import "time"

// runtime.go — explicit scan runtime state (Phase 6).
//
// runScan used to read 15 package globals populated by flag parsing,
// which made data flow invisible and the 30-argument parameter list
// "frozen". ScanRuntime carries that state explicitly: both entry
// points (scan RunE, level shortcuts) build one from their parsed
// flags and hand it to runScan. Reports, auth/API inputs, and target
// selection stay regular parameters — only the cross-cutting runtime
// knobs live here.

// ScanRuntime carries operator runtime knobs from flag parsing into
// runScan. Zero value = safe defaults (passive, sequential legacy is
// NOT default; see Parallel).
type ScanRuntime struct {
	// OOBInteractsh enables the public interactsh fleet for blind
	// SSRF/XXE/Log4Shell confirmation (strictly opt-in).
	OOBInteractsh bool
	// Adversarial + AdversarialConfirmed gate hazardous probes
	// (--adversarial --confirm-authorized; Unsafe implies both).
	Adversarial          bool
	AdversarialConfirmed bool
	// ScopeFile is an allowlist path; targets outside it hard-stop.
	ScopeFile string
	// AutoInstall lets missing binaries self-provision mid-scan.
	AutoInstall bool
	// AssumeYes skips install confirmations (scripts/CI).
	AssumeYes bool
	// Unsafe is the operator master override (implies
	// adversarial+confirmed, lifts safe-purity filters).
	Unsafe bool
	// Parallel runs snapshot-safe stages concurrently (1 = sequential).
	Parallel int
	// Checkpoint/Resume persist per-stage snapshots for interrupted scans.
	Checkpoint string
	Resume     string
	// RiskAccept suppresses listed finding IDs with reason/expiry.
	RiskAccept string
	// Ghost enables undetectable transport (JA3, jitter, canaries).
	Ghost             bool
	GhostCanaryPrefix string
	GhostWorkers      int
	// ProxyPool rotates per-request proxies from a file.
	ProxyPool string
	// Budget caps total scan wall time (0 = uncapped). Queued stages
	// stop between stages with per-phase coverage in the warnings.
	Budget time.Duration
}

// applyUnsafeOverride folds --unsafe into its implied settings.
func (rt *ScanRuntime) applyUnsafeOverride() {
	if rt.Unsafe {
		rt.Adversarial = true
		rt.AdversarialConfirmed = true
	}
}
