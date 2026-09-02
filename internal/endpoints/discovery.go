// Package endpoints converts crawler discoveries into ANPU endpoint
// artifacts and a small amount of informational attack-surface context.
package endpoints

import (
	"context"
	"fmt"

	"github.com/anpu-project/anpu/internal/crawler"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Discovery implements scanner.Scanner for endpoint discovery.
type Discovery struct {
	client *anpuhttp.Client
}

func New(client *anpuhttp.Client) *Discovery { return &Discovery{client: client} }

func (d *Discovery) Name() string { return "endpoints" }

func (d *Discovery) Available(ctx context.Context) bool { return true }

func (d *Discovery) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	limits := crawler.LimitsForProfile(sc.Config.Profile)

	// --- Anonymous pass (always) ---
	anonCrawler := crawler.New(d.client, limits)
	anonEndpoints, warnings, err := anonCrawler.Discover(ctx, sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, fmt.Errorf("crawl target for endpoint discovery: %w", err)
	}

	endpoints := anonEndpoints
	var findings []models.Finding

	// --- Authenticated pass (only when credentials are configured) ---
	if sc.Auth.IsAuthenticated() {
		authClient := d.client.WithAuth(sc.Auth.RequestHeaders())
		authCrawler := crawler.New(authClient, limits)
		authEndpoints, authWarns, authErr := authCrawler.Discover(ctx, sc.Target.Raw)
		warnings = append(warnings, authWarns...)
		if authErr != nil {
			// Authenticated crawl failing is non-fatal: warn and continue
			// with the anonymous surface only.
			warnings = append(warnings, fmt.Sprintf("authenticated crawl failed, using anonymous surface only: %v", authErr))
		} else {
			// Merge authenticated endpoints into the full set and identify
			// those that only appeared behind the credential gate.
			gated := gatedEndpoints(anonEndpoints, authEndpoints)
			endpoints = mergeEndpoints(anonEndpoints, authEndpoints)

			if len(gated) > 0 {
				findings = append(findings, gatedFinding(sc.Target.Raw, string(sc.Auth.EffectiveRole()), gated))
			}
		}
	}

	adminLike := 0
	for _, ep := range endpoints {
		if ep.Category == models.EndpointAdminLike {
			adminLike++
		}
	}
	if adminLike > 0 {
		findings = append(findings, models.Finding{
			ID:              "endpoints-admin-like-discovered",
			Title:           fmt.Sprintf("%d administrative-looking endpoint(s) discovered", adminLike),
			Description:     "One or more discovered endpoints have paths that suggest administrative or privileged functionality. This is informational — it does not by itself mean the endpoint is unprotected — but it narrows the attack surface worth manually reviewing for proper authentication/authorization.",
			Severity:        models.SeverityInfo,
			Confidence:      models.ConfidenceLow,
			Category:        models.CategoryEndpoint,
			Target:          sc.Target.Raw,
			Evidence:        models.Evidence{Observed: fmt.Sprintf("%d admin-like endpoint(s) found during bounded same-origin crawling", adminLike), Location: "HTML/JavaScript content"},
			Source:          models.SourceEndpoints,
			DetectionMethod: "bounded same-origin crawl with HTML/JavaScript extraction",
			Remediation:     "Confirm each administrative endpoint enforces authentication and authorization server-side, independent of whether the URL is publicly discoverable.",
		})
	}

	return scanner.StageResult{Findings: findings, Endpoints: endpoints, Warnings: warnings}, nil
}

// gatedEndpoints returns endpoints that appear in authEndpoints but not in
// anonEndpoints — i.e. URLs only reachable after authentication.
func gatedEndpoints(anon, auth []models.Endpoint) []models.Endpoint {
	anonSet := make(map[string]bool, len(anon))
	for _, ep := range anon {
		anonSet[ep.URL] = true
	}
	var gated []models.Endpoint
	for _, ep := range auth {
		if !anonSet[ep.URL] {
			gated = append(gated, ep)
		}
	}
	return gated
}

// mergeEndpoints combines both endpoint slices, de-duplicating by URL and
// merging source lists. Auth-only endpoints get "crawler-authenticated"
// appended to their source list.
func mergeEndpoints(anon, auth []models.Endpoint) []models.Endpoint {
	index := make(map[string]*models.Endpoint, len(anon))
	out := make([]models.Endpoint, 0, len(anon)+len(auth))

	for i := range anon {
		ep := anon[i]
		out = append(out, ep)
		index[ep.URL] = &out[len(out)-1]
	}
	for _, ep := range auth {
		if existing, ok := index[ep.URL]; ok {
			// Already known — add auth source tag if not present.
			hasAuth := false
			for _, s := range existing.Sources {
				if s == "crawler-authenticated" {
					hasAuth = true
					break
				}
			}
			if !hasAuth {
				existing.Sources = append(existing.Sources, "crawler-authenticated")
			}
		} else {
			// Auth-only endpoint: tag it clearly.
			ep.Sources = append(ep.Sources, "crawler-authenticated")
			out = append(out, ep)
			index[ep.URL] = &out[len(out)-1]
		}
	}
	return out
}

// gatedFinding produces the finding that surfaces auth-only endpoints.
func gatedFinding(target, role string, gated []models.Endpoint) models.Finding {
	// Build a short evidence string listing the first few gated URLs.
	const maxList = 5
	listed := gated
	suffix := ""
	if len(listed) > maxList {
		listed = listed[:maxList]
		suffix = fmt.Sprintf(" … and %d more", len(gated)-maxList)
	}
	var urls string
	for i, ep := range listed {
		if i > 0 {
			urls += ", "
		}
		urls += ep.URL
	}
	urls += suffix

	return models.Finding{
		ID:    "endpoints-authenticated-surface-expanded",
		Title: fmt.Sprintf("%d endpoint(s) only reachable as %q", len(gated), role),
		Description: fmt.Sprintf(
			"An authenticated crawl as %q discovered %d endpoint(s) not visible to anonymous "+
				"requests. These URLs are part of the authenticated attack surface and should be "+
				"reviewed for authorization enforcement, sensitive data exposure, and injection "+
				"vectors. They are passed to all downstream stages (Active, AuthZ, Secrets) for "+
				"further testing.",
			role, len(gated),
		),
		Severity:   models.SeverityInfo,
		Confidence: models.ConfidenceMedium,
		Category:   models.CategoryEndpoint,
		Target:     target,
		Evidence: models.Evidence{
			Observed: fmt.Sprintf("%d gated endpoint(s): %s", len(gated), urls),
			Location: "authenticated bounded same-origin crawl",
		},
		Source:          models.SourceEndpoints,
		DetectionMethod: "two-pass crawl: anonymous baseline vs authenticated follow-up",
		Impact:          "Authenticated endpoints are higher-value targets: they are more likely to process sensitive user data and may assume the caller is already authorized.",
		Remediation:     "Verify each gated endpoint enforces authorization independently — session validation in middleware does not guarantee every route checks resource-level permissions.",
	}
}
