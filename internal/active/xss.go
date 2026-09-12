package active

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// xssRule detects reflected XSS indicators with the corroboration
// contract (see corroboration.go): baseline clean + random control clean
// + reflection context classification. Only reflection in executable
// HTML context (element content or attribute value) keeps High;
// comment/script context is capped at Medium + needs-review, and a
// missing baseline or control degrades to single-technique Medium.
//
// Safety: benign — the payload is non-executable (no <script>), uses a
// fixed canary so it cannot be confused with real content, and is
// GET-only for URL vectors. JSON body injection uses POST but the
// canary is still non-executable.
type xssRule struct{}

func (r *xssRule) ID() models.ActiveRuleID    { return "xss-reflected" }
func (r *xssRule) Name() string               { return "Reflected XSS Indicator" }
func (r *xssRule) Safety() models.SafetyLevel { return models.SafetyBenign }

// RequestBudget covers baseline + probe + random control (+1 headroom).
func (r *xssRule) RequestBudget() int { return 4 }

// xssCanary is injected as a value; we look for it reflected unescaped.
// Using a non-executable tag means no JS runs even if reflected in a browser.
// Ghost mode replaces the anpu prefix via canary.go (no `anpu-` substring).
const xssCanary = `anpu-xss-<b id="anpucanary">`

// xssDetect is the lowercase form we search for in responses.
const xssDetect = `<b id="anpucanary">`

func (r *xssRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	canary, detect := xssCanary, xssDetect
	singleDetect := `<b id='anpucanary'>`
	if GhostEnabled {
		canary, detect = XSSCanary()
		// Derive single-quote variant from the same id
		// detect is like <b id="abcd1234"> → extract id
		var id string
		if idx := strings.Index(detect, `"`); idx >= 0 {
			rest := detect[idx+1:]
			if end := strings.Index(rest, `"`); end >= 0 {
				id = rest[:end]
				singleDetect = strings.Replace(detect, `"`+id+`"`, `'`+id+`'`, 1)
			}
		}
	}
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v, Payload: canary}
	detectLower := strings.ToLower(detect)
	singleLower := strings.ToLower(singleDetect)
	// Second benign tag family for ultra confirmation (<u> vs <b>):
	// derived from the resolved canary so ghost mode stays ghost-clean.
	canary2 := strings.Replace(canary, "<b ", "<u ", 1)
	detect2Lower := strings.ToLower(strings.Replace(detect, "<b ", "<u ", 1))
	single2Lower := strings.ToLower(strings.Replace(singleDetect, "<b ", "<u ", 1))

	// fetch issues one request through the same channel the probe uses
	// (GET for URL vectors, POST for JSON bodies) and reports the
	// lowercased body with its status.
	fetch := func(value string) (bodyLower string, status int, ok bool) {
		var (
			resp *anpuhttp.Response
			err  error
		)
		if v.Kind == models.VectorJSONBody {
			var jsonBody string
			if jsonBody, err = buildJSONBody(v.Name, value); err != nil {
				return "", 0, false
			}
			resp, err = client.PostJSON(ctx, v.URL, jsonBody, nil)
		} else {
			var injected string
			if injected, err = buildInjectedURL(v, value); err != nil {
				return "", 0, false
			}
			resp, err = client.Get(ctx, injected)
		}
		result.RequestsMade++
		if err != nil || resp == nil {
			return "", 0, false
		}
		return strings.ToLower(string(resp.Body)), resp.StatusCode, true
	}

	// --- Baseline: the marker must be absent before injection. ---
	// A page that already contains our canary is indistinguishable from
	// a reflection — fail closed.
	baseLower, _, baseOK := fetch(v.OriginalValue)
	if !baseOK {
		return result, nil
	}
	if strings.Contains(baseLower, detectLower) || strings.Contains(baseLower, singleLower) ||
		strings.Contains(baseLower, detect2Lower) || strings.Contains(baseLower, single2Lower) {
		return result, nil
	}

	// --- Probe: inject the non-executable canary tag. ---
	probeLower, probeStatus, probeOK := fetch(canary)
	if !probeOK {
		return result, nil
	}
	// Check for unescaped reflection — the tag without HTML entity encoding.
	if !strings.Contains(probeLower, detectLower) && !strings.Contains(probeLower, singleLower) {
		return result, nil
	}

	// --- Random control: a benign value must not produce the marker. ---
	// If the marker appears for an unrelated value, the page echoes
	// markers regardless of input and the differential is meaningless.
	controlLower, _, controlOK := fetch(v.OriginalValue + randomBenignToken())
	controlClean := controlOK &&
		!strings.Contains(controlLower, detectLower) &&
		!strings.Contains(controlLower, singleLower)

	context := classifyReflectionContext(probeLower, detectLower)
	if context == CtxUnknown {
		context = classifyReflectionContext(probeLower, singleLower)
	}
	corroborated := controlOK && controlClean

	result.Found = true
	// Only executable HTML context with a clean control earns the full
	// claim; everything else is a single-technique differential.
	if corroborated && isExecutableContext(context) {
		// Ultra-only second family (Phase 3): a distinct benign tag
		// must also reflect unescaped. Two independent reflection
		// families rule out tag-specific echo quirks and earn High
		// confidence. Fits the budget: baseline+probe+control+family2.
		if UltraConfirmEnabled() && result.RequestsMade < r.RequestBudget() {
			fam2Lower, _, fam2OK := fetch(canary2)
			if fam2OK &&
				!strings.Contains(fam2Lower, detectLower) &&
				!strings.Contains(fam2Lower, singleLower) &&
				(strings.Contains(fam2Lower, detect2Lower) || strings.Contains(fam2Lower, single2Lower)) {
				result.Payload = canary + " / " + canary2
				result.Evidence = fmt.Sprintf(
					"Canary %q reflected unescaped in %s context (status %d, baseline clean, random control clean) + ultra second-family %q also reflected unescaped — two independent tag families confirm server-side reflection",
					canary, context, probeStatus, canary2,
				)
				return result, nil
			}
		}
		result.Evidence = fmt.Sprintf(
			"Canary %q reflected unescaped in %s context (status %d, baseline clean, random control clean)",
			canary, context, probeStatus,
		)
		return result, nil
	}
	reason := "non-executable reflection context (" + context + ")"
	if !controlOK {
		reason = "random control unavailable"
	} else if !controlClean {
		// Marker shows up for unrelated input — do not claim at all.
		return models.ActiveRuleResult{RuleID: r.ID(), Vector: v, Payload: canary, RequestsMade: result.RequestsMade}, nil
	}
	result.Evidence = fmt.Sprintf(
		"Canary %q reflected unescaped (status %d) but %s — single-technique differential, needs review (context %s)",
		canary, probeStatus, reason, context,
	)
	return result, nil
}

func (r *xssRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	single := strings.Contains(res.Evidence, SingleTechnique)
	ultra := strings.Contains(res.Evidence, "ultra second-family")
	severity := models.SeverityHigh
	confidence := models.ConfidenceMedium
	method := "reflected XSS canary injection — non-executable <b> tag reflected unescaped in executable HTML context (baseline + random control clean)"
	title := fmt.Sprintf("Reflected XSS indicator in parameter %q at %s", res.Vector.Name, res.Vector.URL)
	if ultra {
		confidence = models.ConfidenceHigh
		method = "reflected XSS canary injection (ultra-confirmed) — two independent benign tag families reflected unescaped in executable HTML context (baseline + random control clean)"
	}
	if single {
		severity = models.SeverityMedium
		method = "reflected XSS canary injection (single-technique) — tag reflected but context non-executable or control unavailable; needs review"
		title = fmt.Sprintf("Possible reflected XSS (single-technique, needs review) in parameter %q at %s", res.Vector.Name, res.Vector.URL)
	}
	var bundle *models.EvidenceBundle
	if single {
		bundle = singleTechniqueBundle(
			fmt.Sprintf("curl -s %q", res.Vector.URL),
			"GET", res.Vector.URL, 0,
			[]string{snippetForEvidence([]byte(res.Evidence))},
		)
	}
	return models.Finding{
		ID:              fmt.Sprintf("active-xss-%d", time.Now().UnixNano()),
		Title:           title,
		Description:     fmt.Sprintf("The parameter %q at %s reflected the injected payload unescaped into the HTML response. This is a strong indicator of reflected cross-site scripting.", res.Vector.Name, res.Vector.URL),
		Severity:        severity,
		Confidence:      confidence,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-79",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: method,
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		EvidenceBundle:  bundle,
		Impact:          "An attacker can inject arbitrary HTML/JavaScript into pages viewed by other users, enabling session hijacking, credential theft, and phishing.",
		Remediation:     "HTML-encode all user-supplied values before rendering them in responses. Use a Content-Security-Policy header to reduce exploitability.",
		References:      []string{"https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
		FirstSeen:       time.Now(),
	}
}

// buildJSONBody creates a single-key JSON object {"name": value} without
// HTML-escaping the value. Standard encoding/json escapes <, >, & by default
// which would corrupt the XSS canary; SetEscapeHTML(false) prevents that.
func buildJSONBody(name, value string) (string, error) {
	m := map[string]string{name: value}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return "", err
	}
	// Encode adds a trailing newline — strip it so the body is compact.
	return strings.TrimRight(buf.String(), "\n"), nil
}
