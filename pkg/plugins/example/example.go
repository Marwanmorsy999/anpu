// Package example is a runnable reference plugin for the ANPU SDK
// (pkg/plugins): a passive generator-meta disclosure check. It runs
// only when explicitly selected (`anpu plugin run --name
// example-generator-meta` or `anpu plugin list`); it is never wired
// into the scan pipeline, so scans are unaffected by its presence.
package example

import (
	"context"
	"strings"

	"github.com/Marwanmorsy999/anpu/pkg/models"
	"github.com/Marwanmorsy999/anpu/pkg/plugins"
)

func init() {
	plugins.Register(GeneratorMeta{})
}

// GeneratorMeta reports generator meta tags, which disclose the exact
// platform (and often version) to anyone who fetches the homepage.
type GeneratorMeta struct{}

// Name implements plugins.Plugin.
func (GeneratorMeta) Name() string { return "example-generator-meta" }

// Description implements plugins.Plugin.
func (GeneratorMeta) Description() string {
	return "Example plugin: generator meta tag disclosure (passive, homepage only)."
}

// Run implements plugins.Plugin.
func (GeneratorMeta) Run(ctx context.Context, target string, fetch plugins.FetchFunc) ([]models.Finding, error) {
	status, _, body, err := fetch(ctx, strings.TrimSuffix(target, "/")+"/")
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, nil
	}
	lower := strings.ToLower(string(body))
	idx := strings.Index(lower, `<meta name="generator"`)
	if idx < 0 {
		return nil, nil
	}
	end := strings.Index(lower[idx:], ">")
	snippet := lower[idx:]
	if end >= 0 && end < 200 {
		snippet = lower[idx : idx+end+1]
	} else if len(snippet) > 200 {
		snippet = snippet[:200] + "..."
	}
	return []models.Finding{{
		ID:              "plugin-example-generator-meta",
		Title:           "Generator meta tag discloses platform",
		Description:     "The homepage carries a generator meta tag, disclosing the exact platform to unauthenticated visitors. Versioned tags let attackers target known CVEs.",
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryTechnology,
		Target:          target,
		URL:             strings.TrimSuffix(target, "/") + "/",
		Source:          models.SourcePlugin,
		DetectionMethod: "example plugin: generator meta marker",
		Remediation:     "Remove the generator meta tag or strip version details.",
		Evidence:        models.Evidence{Observed: "marker matched: " + snippet, Location: "homepage HTML"},
	}}, nil
}
