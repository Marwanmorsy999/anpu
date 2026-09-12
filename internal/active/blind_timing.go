package active

// blind_timing.go — time-based blind injection probe (SQLi / command injection).
//
// Many injections are blind: no error reflection, but the backend can be
// made to sleep. This rule replays a vector with a small set of DB/engine-
// specific sleep payloads and flags when the server takes significantly
// longer to respond than its baseline. All payloads are benign (sleep only,
// no data access, no side effects beyond a short delay).

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

type blindTimingRule struct{}

func (r *blindTimingRule) ID() models.ActiveRuleID    { return "blind-timing" }
func (r *blindTimingRule) Name() string               { return "Blind Timing Injection (SQLi/Cmd)" }
func (r *blindTimingRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *blindTimingRule) RequestBudget() int         { return 7 }

type blindPayload struct {
	payload string
	label   string
	sleep   time.Duration
}

var blindPayloads = []blindPayload{
	{"1' AND SLEEP(5)-- -", "MySQL SLEEP", 5 * time.Second},
	{"1 AND SLEEP(5)-- -", "MySQL SLEEP (no quote)", 5 * time.Second},
	{"'; SELECT pg_sleep(5)--", "PostgreSQL pg_sleep", 5 * time.Second},
	{"' OR pg_sleep(5)--", "PostgreSQL pg_sleep OR", 5 * time.Second},
	{"1; WAITFOR DELAY '0:0:5'--", "MSSQL WAITFOR", 5 * time.Second},
}

// Ultra-only delay-scaling confirmation (Phase 3): a short sleep from
// the same family must also delay, and the long delay must exceed the
// short one by the sleep-argument gap. Coincidental slowness does not
// scale with the injected argument; backend-executed SLEEP does.
const (
	blindConfirmExpect = 4500 * time.Millisecond // long sleep must reach this, twice
	blindDeltaMin      = 4 * time.Second         // long sleep must exceed baseline by this
	ultraShortExpect   = 1500 * time.Millisecond // short sleep must reach this
	ultraScaleMin      = 2000 * time.Millisecond // long must exceed short by this
)

// ultraShortPayload mirrors the first blind family at a shorter delay.
const ultraShortPayload = "1' AND SLEEP(2)-- -"

// scalesWithArgument reports whether two observed delays scale with
// their sleep arguments (pure, unit-tested).
func scalesWithArgument(longElapsed, shortElapsed time.Duration) bool {
	return shortElapsed >= ultraShortExpect && longElapsed-shortElapsed >= ultraScaleMin
}

func (r *blindTimingRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	res := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam {
		return res, nil
	}

	// Baseline: GET with original value, measure elapsed.
	start := time.Now()
	baseResp, err := client.Get(ctx, v.URL)
	res.RequestsMade++
	baseElapsed := time.Since(start)
	if err != nil || baseResp == nil {
		return res, nil
	}
	// If baseline already slow (>3s), skip to avoid false positives on slow endpoints
	if baseElapsed > 3*time.Second {
		return res, nil
	}

	for _, bp := range blindPayloads {
		if res.RequestsMade >= r.RequestBudget() {
			break
		}
		injected, err := buildInjectedURL(v, bp.payload)
		if err != nil {
			continue
		}
		start = time.Now()
		resp, err := client.Get(ctx, injected)
		res.RequestsMade++
		elapsed := time.Since(start)
		if err != nil || resp == nil {
			continue
		}
		// Heuristic: sleep payload should cause elapsed >= 4.5s (5s sleep - jitter)
		// and significantly longer than baseline (+4s). Both must hold to flag.
		if elapsed >= blindConfirmExpect && elapsed-baseElapsed >= blindDeltaMin {
			// Second confirmation to rule out transient slowness
			if res.RequestsMade >= r.RequestBudget() {
				break
			}
			start2 := time.Now()
			resp2, err2 := client.Get(ctx, injected)
			res.RequestsMade++
			elapsed2 := time.Since(start2)
			if err2 != nil || resp2 == nil {
				continue
			}
			if elapsed2 >= blindConfirmExpect {
				res.Found = true
				res.Payload = bp.payload
				res.Evidence = fmt.Sprintf("Blind timing: baseline %v, payload %q (%s) took %v (second probe %v) — server slept ~5s, indicating injection executed.", baseElapsed.Truncate(10*time.Millisecond), bp.payload, bp.label, elapsed.Truncate(10*time.Millisecond), elapsed2.Truncate(10*time.Millisecond))
				// Ultra-only delay scaling (Phase 3): a 2s sleep from
				// the same family must also delay, with the 5s delay
				// exceeding it by the argument gap. Coincidental
				// slowness does not scale with the injected argument.
				// Fits the budget: baseline+long+confirm+short.
				if UltraConfirmEnabled() && res.RequestsMade < r.RequestBudget() {
					if shortURL, serr := buildInjectedURL(v, ultraShortPayload); serr == nil {
						startS := time.Now()
						respS, errS := client.Get(ctx, shortURL)
						res.RequestsMade++
						elapsedS := time.Since(startS)
						if errS == nil && respS != nil && scalesWithArgument(elapsed, elapsedS) {
							res.Evidence = fmt.Sprintf("Blind timing with delay scaling: baseline %v, 5s payload %q took %v (second probe %v), 2s payload took %v — delays scale with the injected sleep argument, confirming backend execution.",
								baseElapsed.Truncate(10*time.Millisecond), bp.payload, elapsed.Truncate(10*time.Millisecond), elapsed2.Truncate(10*time.Millisecond), elapsedS.Truncate(10*time.Millisecond))
						}
					}
				}
				return res, nil
			}
		}
	}
	return res, nil
}

func (r *blindTimingRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	// Double-sleep is a same-family repeat, not a second corroborating
	// family or marker, so timing findings are capped at Medium +
	// review per the contract — unless ultra delay scaling proved the
	// delays track the injected sleep argument (High/High earned).
	scaled := strings.Contains(res.Evidence, "delay scaling")
	severity := models.SeverityMedium
	confidence := models.ConfidenceMedium
	title := fmt.Sprintf("Possible blind time-based injection at %s (timing differential, needs review)", res.Vector.URL)
	method := "time-delta blind injection (timing-differential): baseline vs sleep payload, confirmed twice — same-family repeat, needs review"
	technique := TimingDifferential
	needsReview := true
	if scaled {
		severity = models.SeverityHigh
		confidence = models.ConfidenceHigh
		title = fmt.Sprintf("Blind time-based injection confirmed by delay scaling at %s (ultra-confirmed)", res.Vector.URL)
		method = "time-delta blind injection (ultra-confirmed): 5s and 2s sleep payloads delayed proportionally to their arguments with a clean fast baseline — delay scaling confirms backend execution"
		technique = "delay-scaling-confirmed"
		needsReview = false
	}
	return models.Finding{
		ID:              fmt.Sprintf("active-blind-timing-%d", time.Now().UnixNano()),
		Title:           title,
		Description:     fmt.Sprintf("The endpoint at %s executed a time-delay payload. Probe %q caused the server to delay ~5s (vs baseline). This indicates the backend executed the injected SQL/command. Detection: %s", res.Vector.URL, res.Payload, res.Evidence),
		Severity:        severity,
		Confidence:      confidence,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-89",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: method,
		Evidence: models.Evidence{
			Observed:       res.Evidence,
			Location:       res.Vector.URL,
			RequestSummary: fmt.Sprintf("GET %s with timing payload %q", res.Vector.URL, res.Payload),
		},
		EvidenceBundle: &models.EvidenceBundle{
			Curl:           fmt.Sprintf("curl -s %q", res.Vector.URL),
			RequestMethod:  "GET",
			RequestURL:     res.Vector.URL,
			ResponseStatus: 200,
			Snippets:       []string{snippetForEvidence([]byte(res.Evidence))},
			NeedsReview:    needsReview,
			Technique:      technique,
		},
		Impact:      "An attacker can use time-based blind injection to exfiltrate data or execute commands without needing error reflection, often bypassing WAFs that block error-based payloads.",
		Remediation: "Use parameterized queries / prepared statements, never concatenate input into SQL or shell commands. Validate and escape all input server-side.",
		References: []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
			"https://owasp.org/www-community/attacks/Blind_SQL_Injection",
			"https://cwe.mitre.org/data/definitions/89.html",
		},
		FirstSeen: time.Now(),
	}
}
