package active

// xxe.go — XML External Entity (XXE) injection active rule.
//
// XXE is a vulnerability class where an XML parser processes externally
// defined entity references, allowing an attacker to:
//   - Read arbitrary files from the server (classic XXE via file:// URI)
//   - Perform server-side request forgery (via http:// entity URI)
//   - Cause denial-of-service (billion-laughs entity expansion)
//   - In some configurations, execute remote code
//
// Detection approach (safe, no OOB infrastructure required):
//
//  1. Send a well-formed XML document containing a DOCTYPE declaration with
//     an internal entity reference pointing to a canary path on the same host.
//     This is safe — we reference a path on the target itself, not an external
//     server, so no data leaks to a third party.
//
//  2. If the response body reflects the entity content (the canary string),
//     the parser is expanding entities — definitive XXE signal.
//
//  3. If no reflection: inspect the response for XML parsing error strings
//     that indicate the parser attempted to process the DOCTYPE before rejecting
//     it. This is a weaker signal (Medium confidence) but still actionable.
//
//  4. If the response status changes significantly from baseline (e.g. 200 → 500)
//     after adding the DOCTYPE, that is an indicator the parser is choking on it.
//
// The rule makes at most 2 requests per endpoint:
//   - Request 1: baseline (safe GET or POST with no payload) — used for status diff.
//   - Request 2: XXE probe POST with DOCTYPE + entity reference.
//
// Safety: the payload is a valid XML document; it does not target external
// servers; it cannot modify data. Classified SafetyLowImpact because it
// triggers server-side XML parsing.
//
// CWE-611: Improper Restriction of XML External Entity Reference
// OWASP A05:2021 — Security Misconfiguration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

type xxeRule struct{}

func (r *xxeRule) ID() models.ActiveRuleID    { return "xxe-injection" }
func (r *xxeRule) Name() string               { return "XML External Entity (XXE) Injection" }
func (r *xxeRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *xxeRule) RequestBudget() int         { return 2 }

// xxeErrorSignatures are parser error strings that indicate the server-side
// XML parser processed and rejected the DOCTYPE (weaker signal than reflection).
var xxeErrorSignatures = []string{
	"xml parsing error",
	"xml parse error",
	"xmlparseexception",
	"sax parse",
	"invalid xml",
	"malformed xml",
	"entity",
	"doctype",
	"external entity",
	"xxe",
	"xml external",
	"failed to parse xml",
	"xml syntax error",
	"parseerror",
}

// xxeStackTraceSignatures catch server-side error disclosure triggered by
// malformed entity processing (Java/Python/PHP XML stacks).
var xxeStackTraceSignatures = []string{
	"java.xml",
	"javax.xml",
	"org.xml.sax",
	"com.sun.org.apache.xerces",
	"org.apache.xerces",
	"lxml",
	"xml.etree",
	"simplexml",
	"domdocument",
	"xmlreader",
	"exception in thread",
	"traceback (most recent call last)",
	"at org.xml",
}

// xxeCanaryEntity is the entity name we define in the DOCTYPE.
// The value is a deterministic-looking path segment; the rule generates
// a per-invocation nonce appended to this prefix.
const xxeCanaryEntity = "anpu-xxe-canary"

// buildXXEPayload constructs a well-formed XML document with a DOCTYPE
// that defines an internal entity named xxeCanaryEntity with value nonce,
// then references the entity in the document body.
//
// If the XML parser expands entities, the response body will contain nonce.
// If the parser strips DOCTYPE, the entity reference &anpu-xxe-canary; is
// either dropped or triggers an error — both are detectable signals.
//
// We use an internal entity (value is a literal string, not a URI) so the
// probe never makes outbound connections — safe, no OOB infrastructure needed.
func buildXXEPayload(nonce string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE anpu [
  <!ENTITY %s "%s">
]>
<anpu><probe>&%s;</probe></anpu>`,
		xxeCanaryEntity, nonce, xxeCanaryEntity)
}

// xxeNonce generates a random 8-byte hex string used as the canary value.
// The nonce is short enough to be practical as an entity value but
// distinctive enough to avoid false-positive collisions with page content.
func xxeNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "anpucanary12345678"
	}
	return "anpu-" + hex.EncodeToString(b)
}

func (r *xxeRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	// This rule only handles VectorXMLBody — skip all other vector kinds.
	// The active scanner calls every rule against every vector, so this guard
	// ensures the rule is a no-op when ExtractXMLVectors wasn't the source.
	if v.Kind != models.VectorXMLBody {
		return result, nil
	}

	nonce := xxeNonce()
	payload := buildXXEPayload(nonce)
	result.Payload = payload

	// --- Request 1: baseline GET to capture the normal status code ---
	// We use a lightweight GET to establish a baseline status before probing
	// with POST. This costs one request but allows status-diff detection.
	baselineStatus := 0
	baseResp, baseErr := client.Get(ctx, v.URL)
	result.RequestsMade++
	if baseErr == nil {
		baselineStatus = baseResp.StatusCode
	}

	// --- Request 2: XXE probe POST ---
	probeResp, probeErr := client.PostXML(ctx, v.URL, payload, nil)
	result.RequestsMade++
	if probeErr != nil {
		// Network error — not a finding, not an error (graceful degradation).
		return result, nil
	}

	body := strings.ToLower(string(probeResp.Body))

	// Signal 1 (HIGH confidence): entity reflection.
	// If the response contains our nonce, the parser expanded the entity.
	if strings.Contains(string(probeResp.Body), nonce) {
		result.Found = true
		result.Evidence = fmt.Sprintf(
			"XXE entity reflection confirmed: canary value %q appeared in response body (status %d). "+
				"The XML parser expanded the internal entity defined in the DOCTYPE.",
			nonce, probeResp.StatusCode,
		)
		return result, nil
	}

	// Signal 2 (MEDIUM confidence): parser error strings.
	// The parser attempted to process the DOCTYPE and emitted an error.
	for _, sig := range xxeErrorSignatures {
		if strings.Contains(body, sig) {
			result.Found = true
			result.Evidence = fmt.Sprintf(
				"XML parser error signature %q found in response (status %d) after sending DOCTYPE payload. "+
					"The parser processed the external entity declaration before rejecting it.",
				sig, probeResp.StatusCode,
			)
			return result, nil
		}
	}

	// Signal 3 (MEDIUM confidence): stack trace / library disclosure.
	// An XML library exception was triggered and leaked into the response.
	for _, sig := range xxeStackTraceSignatures {
		if strings.Contains(body, sig) {
			result.Found = true
			result.Evidence = fmt.Sprintf(
				"XML library stack trace indicator %q found in response (status %d) after sending DOCTYPE payload. "+
					"This suggests the XML parser is processing the document and its exceptions are leaking into responses.",
				sig, probeResp.StatusCode,
			)
			return result, nil
		}
	}

	// Signal 4 (LOW confidence): significant status change.
	// A 500 after a 200 baseline suggests the DOCTYPE triggered a server error.
	// Only fire when the baseline was successful (2xx) and probe caused a 5xx.
	if baselineStatus >= 200 && baselineStatus < 300 && probeResp.StatusCode >= 500 {
		result.Found = true
		result.Evidence = fmt.Sprintf(
			"Server returned HTTP %d (baseline was %d) after sending a DOCTYPE payload. "+
				"This may indicate the XML parser is processing the entity declaration and crashing.",
			probeResp.StatusCode, baselineStatus,
		)
		return result, nil
	}

	return result, nil
}

func (r *xxeRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	// Determine confidence from the evidence string — reflection is High;
	// error/stack-trace signals are Medium; status-change is Low.
	confidence := models.ConfidenceMedium
	title := "XML External Entity (XXE) injection indicator"

	ev := res.Evidence
	switch {
	case strings.Contains(ev, "entity reflection confirmed"):
		confidence = models.ConfidenceHigh
		title = "XML External Entity (XXE) injection — entity expansion confirmed"
	case strings.Contains(ev, "stack trace"):
		confidence = models.ConfidenceMedium
		title = "XML External Entity (XXE) injection indicator — library error disclosure"
	case strings.Contains(ev, "Server returned HTTP"):
		confidence = models.ConfidenceLow
		title = "XML External Entity (XXE) injection indicator — abnormal status on DOCTYPE probe"
	}

	return models.Finding{
		ID:    fmt.Sprintf("active-xxe-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("%s at %s", title, res.Vector.URL),
		Description: fmt.Sprintf(
			"The endpoint at %s appears to accept and process XML input without disabling external entity resolution. "+
				"An attacker who can POST crafted XML can exploit XXE to read arbitrary server-side files (e.g. /etc/passwd, application configs), "+
				"perform server-side request forgery by resolving http:// entity URIs, or trigger denial-of-service via recursive entity expansion. "+
				"Detection signal: %s",
			res.Vector.URL, res.Evidence,
		),
		Severity:        models.SeverityCritical,
		Confidence:      confidence,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-611",
		OWASP:           "A05:2021 - Security Misconfiguration",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       "XML request body",
		Source:          models.SourceActive,
		DetectionMethod: "XXE probe: DOCTYPE with internal entity reference; detected via reflection, parser error string, or status change",
		Evidence: models.Evidence{
			Observed:       res.Evidence,
			Location:       res.Vector.URL,
			RequestSummary: fmt.Sprintf("POST %s (Content-Type: application/xml, DOCTYPE entity probe)", res.Vector.URL),
		},
		Impact: "An attacker can read arbitrary files from the server filesystem, perform SSRF to internal services, " +
			"exfiltrate cloud instance metadata (169.254.169.254), or crash the service via entity expansion. " +
			"Impact is critical when the application runs with elevated OS privileges.",
		Remediation: "Disable external entity processing in your XML parser. " +
			"In Java (JAXP): set XMLConstants.FEATURE_SECURE_PROCESSING. " +
			"In Python (lxml): use defusedxml. " +
			"In PHP: libxml_disable_entity_loader(true) (PHP < 8.0) or use the LIBXML_NOENT flag absent. " +
			"Prefer JSON for APIs; if XML is required, use an allowlist schema validator before parsing.",
		References: []string{
			"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
			"https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/611.html",
		},
		FirstSeen: time.Now(),
	}
}
