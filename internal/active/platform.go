package active

import (
	"fmt"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

// platform.go — host-platform artifact filter.
//
// Managed platforms answer certain probes in ways that look like
// vulnerabilities but are expected platform behavior:
//
//   - Vercel/Netlify/Cloudflare (and other edges): Host-header vhost
//     differences are routing, not injection — suppress.
//   - Any confident CDN: cache-varying differentials need the persistence
//     proof (clean re-request); reflection-only candidates demote to a
//     warning until persistence is observed.
//
// Suppression is gated on confident fingerprints (confidence >= 0.8, the
// header/CDN tier — never body-text mentions) so self-hosted targets and
// weak signals still get full findings. Unknown/empty stacks fail open:
// no technologies, no suppression. Suppressed items become warnings, so
// the decision is visible instead of silent.
const platformMinConfidence = 0.8

// edgePlatforms are hosts whose vhost routing makes Host-header
// differentials expected.
var edgePlatforms = []string{
	"vercel", "netlify", "cloudflare", "cloudfront", "akamai",
	"fastly", "azure front door", "aws elb", "elastic load balancer",
}

// confidentTech reports whether technologies contain name (case-insensitive
// substring) at or above the platform confidence gate.
func confidentTech(techs []models.Technology, name string) (string, bool) {
	for _, t := range techs {
		if t.Confidence < platformMinConfidence {
			continue
		}
		if strings.Contains(strings.ToLower(t.Name), strings.ToLower(name)) {
			return t.Name, true
		}
	}
	return "", false
}

// confidentEdge returns the edge platform name when the fingerprinted
// stack confidently says the target sits behind a managed edge.
func confidentEdge(techs []models.Technology) (string, bool) {
	for _, e := range edgePlatforms {
		if name, ok := confidentTech(techs, e); ok {
			return name, true
		}
	}
	return "", false
}

// confidentCDN reports whether any confident CDN fingerprint is present.
func confidentCDN(techs []models.Technology) (string, bool) {
	for _, t := range techs {
		if t.Confidence < platformMinConfidence {
			continue
		}
		if strings.EqualFold(t.Category, "cdn") {
			return t.Name, true
		}
	}
	return "", false
}

// platformFilter demotes expected-platform-behavior findings to warnings.
// It returns the kept findings plus the suppression warnings.
func platformFilter(in []models.Finding, techs []models.Technology) ([]models.Finding, []string) {
	edge, hasEdge := confidentEdge(techs)
	cdn, hasCDN := confidentCDN(techs)
	if !hasEdge && !hasCDN {
		return in, nil
	}
	kept := in[:0]
	var warnings []string
	for _, f := range in {
		switch {
		case hasEdge && strings.HasPrefix(f.ID, "active-host-header-"):
			warnings = append(warnings, fmt.Sprintf(
				"platform-filter: suppressed host-header vhost differential at %s — expected %s routing behavior, not injection",
				f.URL, edge))
		case hasCDN && strings.HasPrefix(f.ID, "active-cache-poison-") && f.Severity != models.SeverityHigh:
			warnings = append(warnings, fmt.Sprintf(
				"platform-filter: cache reflection-only candidate at %s demoted — %s sits in front; persistence proof required for a finding",
				f.URL, cdn))
		default:
			kept = append(kept, f)
		}
	}
	return kept, warnings
}
