package active

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/anpu-project/anpu/pkg/models"
)

// corroboration.go — the official ANPU corroboration contract (Phase 1).
//
// sqli_boolean is the gold standard every active engine moves toward:
//
//	High severity requires: stable baseline + random/control clean +
//	a SECOND corroborating signal (second payload family, backend marker,
//	OOB callback, or an execution proof such as evaluated arithmetic).
//
// A lone differential (one probe family vs baseline) is capped at
// Low/Medium and carries EvidenceBundle{NeedsReview: true,
// Technique: "single-technique"} so reports stay honest about what was
// actually proven. See docs/scoring.md and CHANGELOG (report credibility
// fixes) for the policy history.

// SingleTechnique marks a finding whose only proof is one probe family.
const SingleTechnique = "single-technique"

// DisputedSources marks a dedup-merged finding whose sources disagreed
// meaningfully on severity (set by internal/findings, documented here so
// engines use the same vocabulary).
const DisputedSources = "disputed-sources"

// TimingDifferential tags double-confirmed timing findings: same-family
// repeat, not a second family — Medium at most.
const TimingDifferential = "timing-differential"

// singleTechniqueBundle builds the needs-review bundle for a capped
// differential finding. Curl and snippets keep it reproducible.
func singleTechniqueBundle(curl, method, url string, status int, snippets []string) *models.EvidenceBundle {
	return &models.EvidenceBundle{
		Curl:           curl,
		RequestMethod:  method,
		RequestURL:     url,
		ResponseStatus: status,
		Snippets:       snippets,
		NeedsReview:    true,
		Technique:      SingleTechnique,
	}
}

// signalAbsentInBaseline reports whether sig is absent from the baseline
// body (case-insensitive). A signal already present before injection is
// page chrome, not proof — the probe that "found" it must be discarded.
func signalAbsentInBaseline(baselineLower, sig string) bool {
	return !strings.Contains(baselineLower, strings.ToLower(sig))
}

// randomBenignToken returns a benign control value that carries no markup,
// metacharacters, or canary strings. Controls must never trigger the
// detector themselves; if a control response contains the probe's signal,
// the page is unstable for that signal family.
func randomBenignToken() string {
	return fmt.Sprintf("ctrl-%x", time.Now().UnixNano())
}

// Reflection contexts for classifyReflectionContext.
const (
	// CtxElementContent is normal HTML body text — reflected markup is
	// directly executable HTML.
	CtxElementContent = "element-content"
	// CtxAttribute is inside a tag attribute value — breakout via
	// quote-closing is a real XSS vector.
	CtxAttribute = "attribute"
	// CtxScript is inside a <script> block — the benign tag does not
	// prove JS execution; a breakout payload would be needed.
	CtxScript = "script"
	// CtxHTMLComment is inside <!-- --> — not rendered, not executable.
	CtxHTMLComment = "html-comment"
	// CtxUnknown is returned when the marker is absent.
	CtxUnknown = "unknown"
)

var attrValueTailRe = regexp.MustCompile(`=\s*["'][^"'<>]*$`)

// classifyReflectionContext determines where marker sits in bodyLower
// (both already lowercased). It inspects up to 300 bytes before the
// first marker occurrence.
func classifyReflectionContext(bodyLower, markerLower string) string {
	idx := strings.Index(bodyLower, markerLower)
	if idx < 0 {
		return CtxUnknown
	}
	start := idx - 300
	if start < 0 {
		start = 0
	}
	before := bodyLower[start:idx]
	// HTML comment: last <!-- is newer than the last -->.
	if strings.LastIndex(before, "<!--") > strings.LastIndex(before, "-->") {
		return CtxHTMLComment
	}
	// Script block: last <script is newer than the last </script>.
	if strings.LastIndex(before, "<script") > strings.LastIndex(before, "</script") {
		return CtxScript
	}
	// Attribute value: trailing =["'] with no closing quote yet.
	tail := before
	if len(tail) > 120 {
		tail = tail[len(tail)-120:]
	}
	if attrValueTailRe.MatchString(tail) {
		return CtxAttribute
	}
	return CtxElementContent
}

// isExecutableContext reports whether reflection in ctx is directly
// executable HTML (element content or attribute breakout).
func isExecutableContext(ctx string) bool {
	return ctx == CtxElementContent || ctx == CtxAttribute
}
