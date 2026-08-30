// Package endpoints converts crawler discoveries into ANPU endpoint
// artifacts and a small amount of informational attack-surface context.
package endpoints

import (
	"context"
	"fmt"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/crawler"
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
	c := crawler.New(d.client, limits)
	endpoints, warnings, err := c.Discover(ctx, sc.Target.Raw)
	if err != nil {
		return scanner.StageResult{}, fmt.Errorf("crawl target for endpoint discovery: %w", err)
	}

	adminLike := 0
	for _, ep := range endpoints {
		if ep.Category == models.EndpointAdminLike {
			adminLike++
		}
	}

	var findings []models.Finding
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
