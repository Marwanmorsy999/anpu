package headers

// csp.go — Content-Security-Policy quality analysis.
//
// checkCSPQuality is called by checkCSP when a CSP header is present.
// It parses the policy and emits one finding per identified weakness.
//
// Parser is intentionally minimal: split on ";", split each directive on
// whitespace, lowercase for comparison. No external dependencies.

import (
	"fmt"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

// cspDirective holds a parsed CSP directive name and its source list.
type cspDirective struct {
	name    string
	sources []string
}

// parseCSP splits a CSP header value into directives.
func parseCSP(policy string) []cspDirective {
	var out []cspDirective
	for _, part := range strings.Split(policy, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tokens := strings.Fields(part)
		d := cspDirective{name: strings.ToLower(tokens[0])}
		for _, t := range tokens[1:] {
			d.sources = append(d.sources, strings.ToLower(t))
		}
		out = append(out, d)
	}
	return out
}

// directiveMap indexes parsed directives by name.
func directiveMap(dirs []cspDirective) map[string]cspDirective {
	m := make(map[string]cspDirective, len(dirs))
	for _, d := range dirs {
		m[d.name] = d
	}
	return m
}

// effectiveSources returns the source list for a directive, falling back to
// default-src if the specific directive is absent (mirrors browser behaviour).
func effectiveSources(dm map[string]cspDirective, name string) ([]string, bool) {
	if d, ok := dm[name]; ok {
		return d.sources, true // directive explicitly set
	}
	if def, ok := dm["default-src"]; ok {
		return def.sources, false // inherited from default-src
	}
	return nil, false
}

// hasSource returns true if src appears in the source list.
func hasSource(sources []string, src string) bool {
	for _, s := range sources {
		if s == src {
			return true
		}
	}
	return false
}

// hasWildcard returns true if the source list contains "*" or "http:" or
// "https:" as bare scheme sources (effective wildcards for script loading).
func hasWildcard(sources []string) bool {
	for _, s := range sources {
		if s == "*" || s == "http:" || s == "https:" {
			return true
		}
	}
	return false
}

// checkCSPQuality parses the policy string and returns findings for each
// identified weakness. Called only when CSP is present.
func checkCSPQuality(policy, target, url string, h interface{ Get(string) string }) []models.Finding {
	dirs := parseCSP(policy)
	dm := directiveMap(dirs)

	var out []models.Finding
	ev := models.Evidence{
		Observed: fmt.Sprintf("Content-Security-Policy: %s", policy),
		Location: "HTTP response header",
	}

	// 1. unsafe-inline in script-src / default-src
	scriptSrcs, scriptExplicit := effectiveSources(dm, "script-src")
	directive := "default-src"
	if scriptExplicit {
		directive = "script-src"
	}
	if hasSource(scriptSrcs, "'unsafe-inline'") {
		out = append(out, finding(
			"headers-csp-unsafe-inline",
			fmt.Sprintf("CSP allows 'unsafe-inline' in %s", directive),
			fmt.Sprintf("The Content-Security-Policy sets '%s: ... 'unsafe-inline' ...'. This permits inline <script> blocks and event handlers, which is the most common XSS execution pathway. The protection CSP is meant to provide against XSS is largely negated.", directive),
			models.SeverityMedium,
			models.ConfidenceHigh,
			target, url, ev,
			"Any XSS injection that can place an inline script or event handler executes without restriction, defeating the CSP's XSS mitigation goal.",
			"Remove 'unsafe-inline' from "+directive+". Use nonces ('nonce-<base64>') or hashes ('sha256-<hash>') for legitimate inline scripts instead.",
			"CWE-693",
			[]string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_inline_scripts",
				"https://csp.withgoogle.com/docs/strict-csp.html",
			},
		))
	}

	// 2. unsafe-eval in script-src / default-src
	if hasSource(scriptSrcs, "'unsafe-eval'") {
		out = append(out, finding(
			"headers-csp-unsafe-eval",
			fmt.Sprintf("CSP allows 'unsafe-eval' in %s", directive),
			"The Content-Security-Policy permits eval(), new Function(), and similar dynamic code execution via 'unsafe-eval'. Many JavaScript frameworks use eval() internally, but permitting it in a production CSP significantly broadens the attack surface for DOM-based XSS.",
			models.SeverityLow,
			models.ConfidenceHigh,
			target, url, ev,
			"An attacker who can influence data passed to eval() or Function() can execute arbitrary JavaScript.",
			"Remove 'unsafe-eval'. Audit dependencies for eval() usage and use safer alternatives (e.g. template literals, JSON.parse for data parsing).",
			"CWE-693",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_eval_expressions"},
		))
	}

	// 3. Wildcard or bare scheme in script-src / default-src
	if hasWildcard(scriptSrcs) {
		out = append(out, finding(
			"headers-csp-wildcard-script-src",
			fmt.Sprintf("CSP uses a wildcard or bare scheme in %s", directive),
			fmt.Sprintf("The %s directive contains '*', 'http:', or 'https:' which allows scripts to be loaded from any origin. This is equivalent to having no CSP restriction on script sources.", directive),
			models.SeverityMedium,
			models.ConfidenceHigh,
			target, url, ev,
			"An attacker can load scripts from any host, including attacker-controlled domains, via XSS or HTML injection.",
			"Replace the wildcard with an explicit allowlist of trusted script origins (e.g. 'self', specific CDN domains).",
			"CWE-693",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"},
		))
	}

	// 4. Missing object-src (or not 'none') — classic plugin bypass
	objSrcs, _ := effectiveSources(dm, "object-src")
	if !hasSource(objSrcs, "'none'") {
		out = append(out, finding(
			"headers-csp-missing-object-src-none",
			"CSP does not set object-src 'none'",
			"The policy does not restrict object-src to 'none'. The <object>, <embed>, and <applet> elements can load plugins (Flash, Java applets) that bypass script-src restrictions entirely. Even on modern browsers, missing object-src 'none' leaves a bypass vector.",
			models.SeverityLow,
			models.ConfidenceHigh,
			target, url, ev,
			"An attacker who can inject <object> or <embed> tags can execute arbitrary code via plugins, bypassing script-src.",
			"Add object-src 'none' to the policy.",
			"CWE-693",
			[]string{"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"},
		))
	}

	// 5. Missing base-uri — allows <base> tag injection to hijack relative URLs
	if _, ok := dm["base-uri"]; !ok {
		out = append(out, finding(
			"headers-csp-missing-base-uri",
			"CSP does not set base-uri",
			"The policy does not include a base-uri directive. Without it, an attacker who can inject a <base href='https://evil.example/'> tag can redirect all relative URL fetches (scripts, forms, links) to an attacker-controlled origin.",
			models.SeverityLow,
			models.ConfidenceMedium,
			target, url, ev,
			"An injected <base> tag can silently redirect all relative resource loads to an attacker domain, enabling credential theft and script injection.",
			"Add base-uri 'self' (or 'none') to the policy.",
			"CWE-693",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri"},
		))
	}

	// 6. Missing default-src (no fallback, directives are opt-in only)
	if _, ok := dm["default-src"]; !ok {
		out = append(out, finding(
			"headers-csp-missing-default-src",
			"CSP has no default-src directive",
			"The policy does not include a default-src directive, which serves as the fallback for any fetch directive not explicitly listed. Without it, resource types without an explicit directive (img-src, font-src, etc.) are unrestricted.",
			models.SeverityLow,
			models.ConfidenceMedium,
			target, url, ev,
			"Resource types without an explicit directive in the policy are unrestricted, potentially allowing data exfiltration via unconstrained fetch, img, or font loads.",
			"Add default-src 'self' as a baseline and layer explicit directives on top.",
			"CWE-693",
			[]string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src"},
		))
	}

	return out
}
