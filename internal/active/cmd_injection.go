package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// cmdInjectionRule detects command injection indicators with the
// corroboration contract (see corroboration.go): every signal must be
// baseline-subtracted (absent before injection) and control-clean
// (absent for a benign value). A canary marker differential earns High;
// bare error strings are capped at Medium + single-technique review —
// string matches alone are never Critical. An echo-guard suppresses the
// canary marker when the full payload is reflected verbatim (mere input
// echo, not execution).
//
// Safety: low-impact — uses metacharacters that trigger parse errors
// rather than executing commands. No sleep/ping payloads are used
// (those require timing analysis and carry higher risk).
type cmdInjectionRule struct{}

func (r *cmdInjectionRule) ID() models.ActiveRuleID    { return "cmd-injection-indicator" }
func (r *cmdInjectionRule) Name() string               { return "Command Injection Indicator" }
func (r *cmdInjectionRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }

// RequestBudget covers baseline + random control + up to 3 payload probes.
func (r *cmdInjectionRule) RequestBudget() int { return 5 }

// Payloads use shell metacharacters that cause syntax errors when
// interpolated into a shell command — visible in error output.
// Non-ghost keeps `anpu-cmdi-canary` (YARA allowlist); ghost uses
// CmdPayloads() from canary.go (no `anpu` substring).
var cmdPayloads = []string{
	`|echo anpu-cmdi-canary`,
	`||echo anpu-cmdi-canary`,
	`;echo anpu-cmdi-canary`,
	"`echo anpu-cmdi-canary`",
}

// cmdErrorSignals are error strings that appear when shell metacharacters
// are passed to OS command executors.
var cmdErrorSignals = []string{
	"sh:",
	"/bin/sh",
	"command not found",
	"syntax error",
	"unexpected token",
	"is not recognized as an internal",
	"'echo' is not recognized",
	"anpu-cmdi-canary", // direct execution of our echo
}

func cmdPayloadsForScan() ([]string, []string) {
	if !GhostEnabled {
		return cmdPayloads, cmdErrorSignals
	}
	payloads := CmdPayloads()
	signals := []string{
		"sh:",
		"/bin/sh",
		"command not found",
		"syntax error",
		"unexpected token",
		"is not recognized as an internal",
		"'echo' is not recognized",
		CmdCanary(), // direct execution of our echo
	}
	return payloads, signals
}

// cmdPayloadFamily groups metacharacter payloads so ultra confirmation
// can require two independent families (Phase 3).
func cmdPayloadFamily(payload string) string {
	switch {
	case strings.Contains(payload, "`"):
		return "tick"
	case strings.Contains(payload, ";"):
		return "semi"
	default:
		return "pipe"
	}
}

// cmdMarkerSet returns the canary markers that count as an execution
// marker (corroborating signal earning High) as opposed to bare shell
// error strings, which stay capped at Medium + review.
func cmdMarkerSet() map[string]bool {
	if GhostEnabled {
		return map[string]bool{strings.ToLower(CmdCanary()): true}
	}
	return map[string]bool{"anpu-cmdi-canary": true}
}

func isCmdMarker(sig string, markers map[string]bool) bool {
	return markers[strings.ToLower(sig)]
}

func (r *cmdInjectionRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	fetch := func(value string) (bodyLower string, ok bool) {
		injected, err := buildInjectedURL(v, value)
		if err != nil {
			return "", false
		}
		resp, err := client.Get(ctx, injected)
		result.RequestsMade++
		if err != nil || resp == nil {
			return "", false
		}
		return strings.ToLower(string(resp.Body)), true
	}

	// --- Baseline: signals present before injection are page chrome. ---
	baseLower, baseOK := fetch(v.OriginalValue)
	if !baseOK {
		return result, nil
	}
	// --- Random control: a benign value must not produce signals. ---
	controlLower, controlOK := fetch(v.OriginalValue + randomBenignToken())

	payloads, signals := cmdPayloadsForScan()
	markers := cmdMarkerSet()
	for _, payload := range payloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		probeLower, probeOK := fetch(v.OriginalValue + payload)
		if !probeOK {
			continue
		}
		payloadLower := strings.ToLower(v.OriginalValue + payload)
		for _, sig := range signals {
			sigLower := strings.ToLower(sig)
			if !strings.Contains(probeLower, sigLower) {
				continue
			}
			// Baseline-subtract: pre-existing signal, not proof.
			if !signalAbsentInBaseline(baseLower, sig) {
				continue
			}
			// Control-clean: signal for benign input means the page
			// emits it regardless of injection.
			if controlOK && strings.Contains(controlLower, sigLower) {
				continue
			}
			isMarker := isCmdMarker(sig, markers)
			if isMarker {
				// Echo-guard: verbatim reflection of the full payload
				// is input echo, not command execution.
				if strings.Contains(probeLower, payloadLower) {
					continue
				}
				result.Found = true
				result.Payload = payload
				result.Evidence = fmt.Sprintf(
					"marker=canary canary signal %q present after payload %q in parameter %q but absent in baseline and random control — injected command output observed",
					sig, payload, v.Name,
				)
				return result, nil
			}
			result.Found = true
			result.Payload = payload
			// Ultra-only second family (Phase 3): the same error-signal
			// class from a different metacharacter family rules out
			// payload-specific echo quirks. Two families clear the
			// review flag and raise confidence to Medium.
			if UltraConfirmEnabled() {
				fam1 := cmdPayloadFamily(payload)
				for _, p2 := range payloads {
					if p2 == payload || cmdPayloadFamily(p2) == fam1 {
						continue
					}
					if result.RequestsMade >= r.RequestBudget() {
						break
					}
					probe2, ok2 := fetch(v.OriginalValue + p2)
					if !ok2 || !strings.Contains(probe2, sigLower) {
						continue
					}
					// Baseline/control already vetted for this signal
					// above; presence under a second family corroborates.
					result.Evidence = fmt.Sprintf(
						"signal=error shell error signal %q raised by two metacharacter families (%q and %q) in parameter %q, absent in baseline and random control — ultra second-family corroboration, review cleared",
						sig, payload, p2, v.Name,
					)
					return result, nil
				}
			}
			result.Evidence = fmt.Sprintf(
				"signal=error shell error signal %q found after payload %q in parameter %q but absent in baseline and random control — single-technique differential, needs review",
				sig, payload, v.Name,
			)
			return result, nil
		}
	}
	return result, nil
}

func (r *cmdInjectionRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	// The canary marker differential earns High; bare error strings are
	// capped at Medium + single-technique review, unless ultra
	// second-family corroboration clears the review (Medium/Medium).
	// Nothing here is ever Critical — a string match alone cannot
	// confirm remote execution.
	severity := models.SeverityMedium
	confidence := models.ConfidenceLow
	method := "command injection probe (single-technique): shell error string differentially present vs baseline + control — Medium, needs review"
	title := fmt.Sprintf("Possible command injection (single-technique, needs review) in parameter %q at %s", res.Vector.Name, res.Vector.URL)
	var bundle *models.EvidenceBundle
	if strings.Contains(res.Evidence, "marker=canary") {
		severity = models.SeverityHigh
		method = "command injection probe: canary marker differentially present vs baseline + control with echo-guard (baseline-subtracted execution signal)"
		title = fmt.Sprintf("Command injection indicator in parameter %q at %s", res.Vector.Name, res.Vector.URL)
	} else if strings.Contains(res.Evidence, "ultra second-family") {
		confidence = models.ConfidenceMedium
		method = "command injection probe (ultra-confirmed): same error-signal class from two metacharacter families vs baseline + control — review cleared"
		title = fmt.Sprintf("Command injection indicator (ultra-confirmed, two families) in parameter %q at %s", res.Vector.Name, res.Vector.URL)
	} else {
		bundle = singleTechniqueBundle(
			fmt.Sprintf("curl -s %q", res.Vector.URL),
			"GET", res.Vector.URL, 0,
			[]string{snippetForEvidence([]byte(res.Evidence))},
		)
	}
	return models.Finding{
		ID:              fmt.Sprintf("active-cmdi-%d", time.Now().UnixNano()),
		Title:           title,
		Description:     fmt.Sprintf("Shell metacharacters injected into parameter %q produced a shell error message or executed a test command, indicating the value is passed to a system shell without sanitization.", res.Vector.Name),
		Severity:        severity,
		Confidence:      confidence,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-78",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: method,
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload appended to %s)", res.Vector.URL, res.Vector.Name)},
		EvidenceBundle:  bundle,
		Impact:          "An attacker can execute arbitrary commands on the server operating system, leading to full server compromise.",
		Remediation:     "Never pass user input to shell commands. Use language APIs that accept argument lists instead of shell strings. Validate input against strict allowlists.",
		References:      []string{"https://owasp.org/www-community/attacks/Command_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"},
		FirstSeen:       time.Now(),
	}
}
