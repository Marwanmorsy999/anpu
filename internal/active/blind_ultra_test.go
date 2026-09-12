package active

import (
	"testing"
	"time"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Phase 3: delay scaling is pure arithmetic — lock the gate before
// trusting it to mint High/High findings.
func TestScalesWithArgument(t *testing.T) {
	if !scalesWithArgument(5200*time.Millisecond, 2100*time.Millisecond) {
		t.Fatal("5.2s vs 2.1s must scale")
	}
	if scalesWithArgument(5200*time.Millisecond, 500*time.Millisecond) {
		t.Fatal("short delay below floor must not scale")
	}
	if scalesWithArgument(5200*time.Millisecond, 4500*time.Millisecond) {
		t.Fatal("flat delays must not scale (no argument gap)")
	}
	if scalesWithArgument(0, 0) {
		t.Fatal("zero delays must not scale")
	}
}

func TestBlindTimingToFindingScaledVsCapped(t *testing.T) {
	scaled := models.ActiveRuleResult{
		RuleID:   "blind-timing",
		Vector:   models.InputVector{URL: "https://example.com/?q=1", Kind: models.VectorQueryParam, Name: "q"},
		Payload:  "1' AND SLEEP(5)-- -",
		Evidence: "Blind timing with delay scaling: baseline 100ms, 5s payload took 5.1s (second probe 5.0s), 2s payload took 2.1s — delays scale with the injected sleep argument, confirming backend execution.",
		Found:    true,
	}
	f := (&blindTimingRule{}).ToFinding(scaled, "https://example.com")
	if f.Severity != models.SeverityHigh || f.Confidence != models.ConfidenceHigh {
		t.Fatalf("scaled must be High/High, got %s/%s", f.Severity, f.Confidence)
	}
	if f.EvidenceBundle == nil || f.EvidenceBundle.NeedsReview || f.EvidenceBundle.Technique != "delay-scaling-confirmed" {
		t.Fatalf("scaled bundle wrong: %+v", f.EvidenceBundle)
	}

	plain := scaled
	plain.Evidence = "Blind timing: baseline 100ms, payload took 5.1s (second probe 5.0s) — server slept ~5s, indicating injection executed."
	f2 := (&blindTimingRule{}).ToFinding(plain, "https://example.com")
	if f2.Severity != models.SeverityMedium || f2.Confidence != models.ConfidenceMedium {
		t.Fatalf("unscaled must stay Medium/Medium, got %s/%s", f2.Severity, f2.Confidence)
	}
	if f2.EvidenceBundle == nil || !f2.EvidenceBundle.NeedsReview {
		t.Fatal("unscaled must keep review bundle")
	}
}
