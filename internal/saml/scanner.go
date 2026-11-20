// Package saml checks SAML metadata exposure (Wave 1 item 16): SP/IdP
// metadata documents at well-known paths. At most 5 requests, GET-only.
// An EntityDescriptor with SSO endpoints is an Info finding (federation
// surface for AuthZ review) plus harvested Endpoints.
//
// No AuthnRequests are sent and no login is attempted.
package saml

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/fpmatch"
	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "samlmetadata" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var (
	entityRe   = regexp.MustCompile(`(?i)<(?:md:)?EntityDescriptor[^>]*entityID\s*=\s*["']([^"']+)["']`)
	endpointRe = regexp.MustCompile(`(?i)Location\s*=\s*["'](https?://[^"']+)["']`)
)

var samlPaths = []string{
	"/saml/metadata",
	"/saml2/metadata",
	"/shibboleth",
	"/FederationMetadata/2007-06/FederationMetadata.xml",
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (result scanner.StageResult, err error) {
	budgetExhausted := false
	defer func() {
		if budgetExhausted {
			result.Warnings = append(result.Warnings, scanner.BudgetExhaustedWarning(sc))
		}
	}()
	get := func(path string) *anpuhttp.Response {
		if err := scanner.ChargeBudget(sc); err != nil {
			budgetExhausted = true
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		resp, err := s.client.Get(cctx, strings.TrimSuffix(sc.Target.Raw, "/")+path)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	controlLen := -1
	if control := get("/anpu-saml-control-404"); control != nil {
		controlLen = len(control.Body) / 256
	}

	var findings []models.Finding
	var endpoints []models.Endpoint
	for _, p := range samlPaths {
		resp := get(p)
		if budgetExhausted {
			break
		}
		if resp == nil || resp.StatusCode != 200 || len(resp.Body) < 100 {
			continue
		}
		m := entityRe.FindStringSubmatch(string(resp.Body))
		if m == nil {
			continue
		}
		if fpmatch.IsWAFBlockPage(resp.Body) {
			continue // WAF block page served as 200, not metadata
		}
		if controlLen >= 0 && len(resp.Body)/256 == controlLen && !strings.Contains(strings.ToLower(string(resp.Body)), "entitydescriptor") {
			continue // baseline-subtract (defensive; marker already required)
		}
		seen := map[string]bool{}
		for _, em := range endpointRe.FindAllStringSubmatch(string(resp.Body), -1) {
			u := em[1]
			if seen[u] || len(endpoints) >= 10 {
				continue
			}
			seen[u] = true
			endpoints = append(endpoints, models.Endpoint{URL: u, Category: models.EndpointAuth, Sources: []string{"saml-metadata"}})
		}
		findings = append(findings, models.Finding{
			ID:              "samlmetadata-exposed",
			Title:           "SAML metadata document exposed",
			Description:     fmt.Sprintf("The path %s serves a SAML EntityDescriptor (entityID %q). Metadata names SSO endpoints and certificate use — review bindings (prefer HTTP-Redirect + signed AuthnRequests) and expiry. Reproduce: curl -s TARGET%s.", p, m[1], p),
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceHigh,
			Category:        models.CategoryExposure,
			Target:          sc.Target.Raw,
			URL:             strings.TrimSuffix(sc.Target.Raw, "/") + p,
			Evidence:        models.Evidence{Observed: "entityID: " + m[1], Location: p},
			Source:          models.SourceRecon,
			DetectionMethod: "SAML metadata marker probe (samlmetadata, ≤5 requests)",
		})
		break // one metadata document is enough
	}
	return scanner.StageResult{Findings: findings, Endpoints: endpoints}, nil
}
