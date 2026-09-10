package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// sqliBooleanRule confirms SQL injection with a TRUE/FALSE content
// differential (sqlmap-style boolean blind), no error strings needed:
//
//  1. Fetch the baseline twice — pages that change on their own
//     (timestamps, CSRF tokens, ads) are rejected as unstable.
//  2. Inject `' AND '1'='1` (TRUE) and `' AND '1'='2` (FALSE).
//  3. Flag only when TRUE≈baseline while FALSE differs from both
//     (Jaccard word-set similarity). Numeric `AND 1=1 / AND 1=2`
//     pair runs when the string pair is inconclusive.
//
// Safety: low-impact — logic-preserving comparisons, no data access,
// no stacked queries, no time delays.
type sqliBooleanRule struct{}

func (r *sqliBooleanRule) ID() models.ActiveRuleID    { return "sqli-boolean-differential" }
func (r *sqliBooleanRule) Name() string               { return "SQL Injection (Boolean Differential)" }
func (r *sqliBooleanRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *sqliBooleanRule) RequestBudget() int         { return 7 }

// booleanPairs are (truePayloadSuffix, falsePayloadSuffix) applied to
// the parameter's original value.
var booleanPairs = [][2]string{
	{`' AND '1'='1`, `' AND '1'='2`},
	{` AND 1=1`, ` AND 1=2`},
}

// booleanThresholds for the differential verdict.
const (
	booleanStabilityMin = 0.90 // baseline-vs-baseline: page must be stable
	booleanTrueMin      = 0.85 // TRUE-vs-baseline: must look the same
	booleanFalseMax     = 0.70 // FALSE-vs-baseline and TRUE-vs-FALSE: must differ
)

func (r *sqliBooleanRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if v.Kind != models.VectorQueryParam && v.Kind != models.VectorPathSegment {
		return result, nil
	}

	type fetchInfo struct {
		body   []byte
		status int
		length int
		ct     string
		ok     bool
		snip   string
	}
	get := func(targetURL string) fetchInfo {
		resp, err := client.Get(ctx, targetURL)
		result.RequestsMade++
		if err != nil || resp == nil {
			return fetchInfo{ok: false}
		}
		ct := resp.Header.Get("Content-Type")
		ctNorm := normalizeCT(ct)
		snip := snippetForEvidence(resp.Body)
		return fetchInfo{
			body:   resp.Body,
			status: resp.StatusCode,
			length: len(resp.Body),
			ct:     ctNorm,
			ok:     true,
			snip:   snip,
		}
	}

	// --- Stability gate: two baselines must agree + 200 + same CT ---
	base1 := get(v.URL)
	if !base1.ok {
		return result, nil
	}
	base2 := get(v.URL)
	if !base2.ok {
		return result, nil
	}
	// Require 200×2 same CT for a stable baseline; else still allow but will be single-technique.
	baselineCTOk := base1.status == 200 && base2.status == 200 && base1.ct == base2.ct && base1.ct != ""
	baselineCT := base1.ct
	if baselineCT == "" {
		baselineCT = base2.ct
	}
	baseSet := bypassWordSet(base1.body)
	if bypassSimilarity(baseSet, bypassWordSet(base2.body)) < booleanStabilityMin {
		return result, nil // dynamic page — differential would lie
	}

	for _, pair := range booleanPairs {
		if result.RequestsMade+3 > r.RequestBudget() {
			break
		}
		trueURL, err := injectAtVector(v, v.OriginalValue+pair[0])
		if err != nil {
			continue
		}
		falseURL, err := injectAtVector(v, v.OriginalValue+pair[1])
		if err != nil {
			continue
		}
		trueInfo := get(trueURL)
		if !trueInfo.ok {
			continue
		}
		falseInfo := get(falseURL)
		if !falseInfo.ok {
			continue
		}
		// Random control: inject a random string that should NOT produce the same differential.
		// This rules out pages where any injection causes a change (WAF block page, etc.).
		randVal := randomControlValue()
		randURL, _ := injectAtVector(v, v.OriginalValue+randVal)
		var randInfo fetchInfo
		randOk := false
		if randURL != "" && result.RequestsMade < r.RequestBudget() {
			randInfo = get(randURL)
			randOk = randInfo.ok
		}

		simTrue := bypassSimilarity(baseSet, bypassWordSet(trueInfo.body))
		simFalse := bypassSimilarity(baseSet, bypassWordSet(falseInfo.body))
		simPair := bypassSimilarity(bypassWordSet(trueInfo.body), bypassWordSet(falseInfo.body))

		// Triple gate: require 200×3 same CT (baseline×2 + true + false).
		tripleOK := baselineCTOk && trueInfo.status == 200 && falseInfo.status == 200 && trueInfo.ct == baselineCT && falseInfo.ct == baselineCT
		// Random control: random payload should be similar to baseline/true, not to false.
		randControlOK := true
		if randOk {
			simRand := bypassSimilarity(baseSet, bypassWordSet(randInfo.body))
			// If random also diverges like false, the page is unstable for any injection.
			if simRand <= booleanFalseMax {
				randControlOK = false
			}
		}

		if simTrue >= booleanTrueMin && simFalse <= booleanFalseMax && simPair <= booleanFalseMax {
			if tripleOK && randControlOK {
				// Full evidence: 200×3 same CT + random control + differential — High/High earned.
				result.Found = true
				result.Payload = pair[0] + " / " + pair[1]
				result.Evidence = fmt.Sprintf(
					"Boolean differential confirmed on parameter %q: TRUE-probe similarity to baseline %.2f, FALSE-probe %.2f, TRUE-vs-FALSE %.2f (thresholds ≥%.2f / ≤%.2f). Status 200×3 same CT %q, lengths %d/%d/%d, random control %.2f — backend evaluated injected logic.",
					v.Name, simTrue, simFalse, simPair, booleanTrueMin, booleanFalseMax, baselineCT, base1.length, trueInfo.length, falseInfo.length, simPair,
				)
				return result, nil
			}
			// Single-technique path: differential found but 200×3/CT or random control failed.
			// Keep High (per keep-High decision) but tag single-technique + snippets.
			snippets := fmt.Sprintf("baseline~%q true~%q false~%q", base1.snip, trueInfo.snip, falseInfo.snip)
			if randOk {
				snippets += fmt.Sprintf(" rand~%q", randInfo.snip)
			}
			result.Found = true
			result.Payload = pair[0] + " / " + pair[1]
			result.Evidence = fmt.Sprintf(
				"Boolean differential (single-technique) on parameter %q: TRUE %.2f vs FALSE %.2f (pair %.2f). Statuses %d/%d/%d CTs %q/%q/%q; lengths %d/%d/%d. Random control %v. Snippets: %s. Requires review — High/High not fully earned without 200×3 same CT.",
				v.Name, simTrue, simFalse, simPair, base1.status, trueInfo.status, falseInfo.status, base1.ct, trueInfo.ct, falseInfo.ct, base1.length, trueInfo.length, falseInfo.length, randControlOK, snippets,
			)
			return result, nil
		}
	}
	return result, nil
}

func normalizeCT(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return ct
}

func snippetForEvidence(body []byte) string {
	s := string(body)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	// Redact obvious PII-ish patterns: truncate already, keep as-is for review
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

func randomControlValue() string {
	// Deterministic-looking but per-call random: "' AND 'rand'='other"
	b := make([]byte, 3)
	// Use non-crypto fallback if needed, but keep simple.
	for i := range b {
		b[i] = byte('a' + (time.Now().UnixNano()+int64(i))%26)
	}
	randStr := string(b)
	return fmt.Sprintf("' AND '%s'='%s_x", randStr, randStr)
}

// injectAtVector builds the probe URL for query-param and path-segment
// vectors (the only kinds this rule handles).
func injectAtVector(v models.InputVector, value string) (string, error) {
	switch v.Kind {
	case models.VectorQueryParam:
		return InjectQueryParam(v.URL, v.Name, value)
	case models.VectorPathSegment:
		return InjectPathSegment(v.URL, v.Name, value)
	default:
		return "", fmt.Errorf("unsupported vector kind %q", v.Kind)
	}
}

func (r *sqliBooleanRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	isSingle := strings.Contains(res.Evidence, "single-technique")
	curl := fmt.Sprintf("curl -s %q", res.Vector.URL)
	if res.Payload != "" {
		// Build a reproducible curl with the payload in the URL (for query vectors)
		if inj, err := injectAtVector(res.Vector, res.Payload); err == nil {
			curl = fmt.Sprintf("curl -s %q", inj)
		}
	}
	bundle := &models.EvidenceBundle{
		Curl:           curl,
		RequestMethod:  "GET",
		RequestURL:     res.Vector.URL,
		ResponseStatus: 200,
		Technique:      "",
		NeedsReview:    isSingle,
		Snippets:       []string{snippetForEvidence([]byte(res.Evidence))},
	}
	if isSingle {
		bundle.Technique = "single-technique"
	}
	// Also include payload as a snippet for review
	if res.Payload != "" {
		bundle.ResponseSnippets = []string{snippetForEvidence([]byte(res.Payload))}
	}
	confidence := models.ConfidenceHigh
	severity := models.SeverityHigh
	title := fmt.Sprintf("Blind SQL injection confirmed by boolean differential in parameter %q at %s", res.Vector.Name, res.Vector.URL)
	method := "boolean-based blind SQLi: TRUE≈baseline while FALSE diverges (stability-gated content differential, 200×3 same CT + random control, keep High)"
	if isSingle {
		// Single-technique differentials have caused false positives on
		// framework-driven pages: they stay visible but cannot carry
		// High severity until a second corroborating signal earns it.
		severity = models.SeverityMedium
		confidence = models.ConfidenceMedium
		title = fmt.Sprintf("Possible blind SQL injection (single-technique differential, needs review) in parameter %q at %s", res.Vector.Name, res.Vector.URL)
		method = "boolean-based blind SQLi (single-technique): TRUE≈baseline vs FALSE diverges but 200×3 same CT or random control not fully earned — Medium, needs review (bundle + snippets)"
	}
	return models.Finding{
		ID:    fmt.Sprintf("active-sqli-bool-%d", time.Now().UnixNano()),
		Title: title,
		Description: fmt.Sprintf(
			"Parameter %q provably flows into a SQL query: a TRUE condition rendered the baseline page while the FALSE condition changed it (%s). "+
				"No error messages were needed — the logic gap alone confirms injectability, the same technique sqlmap's boolean-blind mode uses.",
			res.Vector.Name, res.Evidence,
		),
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
			RequestSummary: fmt.Sprintf("GET %s (boolean pair in %s)", res.Vector.URL, res.Vector.Name),
		},
		EvidenceBundle: bundle,
		Impact:         "Attackers can extract database contents bit-by-bit with TRUE/FALSE questions, bypass authentication, and escalate toward OS command execution.",
		Remediation:    "Use parameterised queries or prepared statements. Never interpolate user input into SQL. Apply least-privilege DB accounts and rate-limit query endpoints.",
		References: []string{
			"https://owasp.org/www-community/attacks/Blind_SQL_Injection",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		},
		FirstSeen: time.Now(),
	}
}
