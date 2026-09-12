// Package adaptive classifies the discovered attack surface after the
// Discovery phase so later stages can skip work that cannot pay off.
//
// A static-marketing surface (SSG fingerprint, no API routes, no auth
// surface, no forms, no parameterized URLs, unauthenticated) has no
// server-side injection surface: SQLi, SSTI, LFI, backup-file, and
// command-injection stages skip with a logged reason instead of burning
// ~25 minutes of probes. Anything else — including empty Discovery data
// (custom --only runs) — fails open to the full battery.
package adaptive

import (
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

// Surface classes.
const (
	ClassApp             = "app"
	ClassStaticMarketing = "static-marketing"
)

// staticSiteTechs are fingerprints that mean "no operator backend code".
var staticSiteTechs = []string{
	"gatsby", "hugo", "jekyll", "astro", "wix", "squarespace", "webflow",
}

// StaticMarketingSkipRules are active-engine rule IDs with no payoff on a
// static-marketing surface (server-side injection families).
var StaticMarketingSkipRules = map[string]bool{
	"sqli-error-based":          true,
	"sqli-boolean-differential": true,
	"ssti-math-probe":           true,
	"path-traversal":            true,
	"cmd-injection-indicator":   true,
}

// SurfaceClass classifies the discovered surface. endpoints and techs are
// Discovery outputs; authed reports whether the scan carries credentials.
// Empty Discovery data fails open to ClassApp (custom --only selections
// must never lose coverage to a classifier that saw nothing).
func SurfaceClass(endpoints []models.Endpoint, techs []models.Technology, authed bool) (class, reason string) {
	if len(endpoints) == 0 && len(techs) == 0 {
		return ClassApp, "no discovery data — full battery (fail-open)"
	}
	if authed {
		return ClassApp, "authenticated scan — full battery"
	}
	for _, ep := range endpoints {
		switch ep.Category {
		case models.EndpointAPI, models.EndpointAuth, models.EndpointAdminLike:
			return ClassApp, "API/auth surface present — full battery"
		}
		if strings.Contains(ep.URL, "?") {
			return ClassApp, "parameterized URLs present — full battery"
		}
		if strings.TrimSpace(ep.Method) != "" {
			return ClassApp, "forms present — full battery"
		}
	}
	if !hasStaticSiteTech(techs) {
		return ClassApp, "no static-site fingerprint — full battery"
	}
	return ClassStaticMarketing, "static-marketing surface (SSG, no API/auth/forms/params) — server-side injection stages skipped"
}

func hasStaticSiteTech(techs []models.Technology) bool {
	for _, t := range techs {
		n := strings.ToLower(t.Name)
		for _, s := range staticSiteTechs {
			if strings.Contains(n, s) {
				return true
			}
		}
	}
	return false
}
