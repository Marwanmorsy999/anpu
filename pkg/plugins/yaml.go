package plugins

import (
	"context"
	"crypto/sha1" // #nosec G505 -- SHA-1 derives stable non-secret finding IDs only; never integrity or secrecy.
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Check is one declarative detection in a YAML plugin file: fetch path,
// match the body against a RE2 regex, emit a finding on match. Pure
// fetch-and-match — no scripting, no network beyond FetchFunc.
type Check struct {
	// Name is the human label, namespaced into finding IDs.
	Name string `yaml:"name"`
	// Path is the absolute request path (must start with "/").
	Path string `yaml:"path"`
	// Match is a Go (RE2) regex tested against the response body.
	Match string `yaml:"match"`
	// Title is the finding title on match.
	Title string `yaml:"title"`
	// Description explains the issue.
	Description string `yaml:"description"`
	// Severity, Confidence, Category use the models vocabularies.
	Severity   models.Severity   `yaml:"severity"`
	Confidence models.Confidence `yaml:"confidence"`
	Category   models.Category   `yaml:"category"`
	// Remediation is optional fix guidance.
	Remediation string `yaml:"remediation,omitempty"`

	matchRe *regexp.Regexp
}

// pluginFile is the on-disk YAML shape.
type pluginFile struct {
	Checks []Check `yaml:"checks"`
}

// knownCategories bounds Category to values the pipeline understands.
var knownCategories = map[models.Category]bool{
	models.CategoryHeaders: true, models.CategoryCookies: true,
	models.CategoryTLS: true, models.CategoryTechnology: true,
	models.CategoryExposure: true, models.CategoryEndpoint: true,
	models.CategoryConfiguration: true, models.CategoryVulnerability: true,
	models.CategoryAuthentication: true, models.CategoryOther: true,
}

// LoadChecks parses and validates a YAML plugin file. Every check is
// validated up front (vocabularies, path shape, regex compiles) so a
// broken file fails fast instead of half-running.
func LoadChecks(path string) ([]Check, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-specified plugin file path.
	if err != nil {
		return nil, fmt.Errorf("reading plugin file %s: %w", path, err)
	}
	var doc pluginFile
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing plugin file %s: %w", path, err)
	}
	if len(doc.Checks) == 0 {
		return nil, fmt.Errorf("plugin file %s defines no checks", path)
	}
	for i := range doc.Checks {
		if err := doc.Checks[i].validate(); err != nil {
			return nil, fmt.Errorf("plugin file %s check %d: %w", path, i, err)
		}
	}
	return doc.Checks, nil
}

func (c *Check) validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("check has no name")
	}
	if !strings.HasPrefix(c.Path, "/") {
		return fmt.Errorf("check %q: path %q must start with \"/\"", c.Name, c.Path)
	}
	if strings.TrimSpace(c.Match) == "" {
		return fmt.Errorf("check %q: empty match regex", c.Name)
	}
	re, err := regexp.Compile(c.Match)
	if err != nil {
		return fmt.Errorf("check %q: invalid match regex: %w", c.Name, err)
	}
	c.matchRe = re
	if strings.TrimSpace(c.Title) == "" {
		return fmt.Errorf("check %q: empty title", c.Name)
	}
	if !c.Severity.Valid() {
		return fmt.Errorf("check %q: invalid severity %q", c.Name, c.Severity)
	}
	if !c.Confidence.Valid() {
		return fmt.Errorf("check %q: invalid confidence %q", c.Name, c.Confidence)
	}
	if !knownCategories[c.Category] {
		return fmt.Errorf("check %q: invalid category %q", c.Name, c.Category)
	}
	return nil
}

// stableID derives a deterministic finding ID from check name + path so
// reruns and diffs see the same issue as the same finding.
func (c *Check) stableID() string {
	h := sha1.New() // #nosec G401 -- content-derived stable IDs only, never integrity or secrecy.
	h.Write([]byte(c.Name + "|" + c.Path))
	return "plugin-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// RunChecks executes validated checks against target via fetch and
// returns one finding per match. Non-2xx responses never match: absence
// of evidence is not evidence, and soft-404 bodies must not become
// findings from a coincidental regex hit on an error page.
func RunChecks(ctx context.Context, target string, checks []Check, fetch FetchFunc) ([]models.Finding, error) {
	var out []models.Finding
	base := strings.TrimSuffix(target, "/")
	for _, c := range checks {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		fullURL := base + c.Path
		status, _, body, err := fetch(ctx, fullURL)
		if err != nil {
			return out, fmt.Errorf("check %q: fetch %s: %w", c.Name, fullURL, err)
		}
		if status < 200 || status >= 300 {
			continue
		}
		loc := c.matchRe.FindIndex(body)
		if loc == nil {
			continue
		}
		snippet := string(body[loc[0]:loc[1]])
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		out = append(out, models.Finding{
			ID:              c.stableID(),
			Title:           c.Title,
			Description:     c.Description,
			Severity:        c.Severity,
			Confidence:      c.Confidence,
			Category:        c.Category,
			Target:          target,
			URL:             fullURL,
			Source:          models.SourcePlugin,
			DetectionMethod: "plugin check: " + c.Name,
			Remediation:     c.Remediation,
			Evidence: models.Evidence{
				Observed: "marker matched at " + fullURL + ": " + snippet,
				Location: fullURL,
			},
		})
	}
	return out, nil
}
