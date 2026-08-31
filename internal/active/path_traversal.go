package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// pathTraversalRule detects path traversal by injecting sequences that
// attempt to read /etc/passwd (Linux) or win.ini (Windows) and checking
// for recognisable content in the response.
//
// Safety: benign — reads a well-known read-only system file.
type pathTraversalRule struct{}

func (r *pathTraversalRule) ID() models.ActiveRuleID  { return "path-traversal" }
func (r *pathTraversalRule) Name() string             { return "Path Traversal" }
func (r *pathTraversalRule) Safety() models.SafetyLevel { return models.SafetyBenign }
func (r *pathTraversalRule) RequestBudget() int       { return 3 }

var traversalPayloads = []struct {
	payload  string
	signal   string
}{
	{`../../../etc/passwd`, `root:`},
	{`....//....//....//etc/passwd`, `root:`},
	{`..%2F..%2F..%2Fetc%2Fpasswd`, `root:`},
	{`../../../windows/win.ini`, `[extensions]`},
	{`..%5C..%5C..%5Cwindows%5Cwin.ini`, `[extensions]`},
}

func (r *pathTraversalRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	for _, probe := range traversalPayloads {
		if result.RequestsMade >= r.RequestBudget() {
			break
		}
		injected, err := buildInjectedURL(v, probe.payload)
		if err != nil {
			continue
		}
		resp, err := client.Get(ctx, injected)
		result.RequestsMade++
		if err != nil {
			continue
		}
		body := string(resp.Body)
		if strings.Contains(body, probe.signal) {
			result.Found = true
			result.Payload = probe.payload
			result.Evidence = fmt.Sprintf(
				"Path traversal payload %q produced signal %q in response (status %d)",
				probe.payload, probe.signal, resp.StatusCode,
			)
			return result, nil
		}
	}
	return result, nil
}

func (r *pathTraversalRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID: fmt.Sprintf("active-traversal-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("Path traversal in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description: fmt.Sprintf("The payload %q caused the server to include the contents of a system file in its response, confirming a path traversal vulnerability in parameter %q.", res.Payload, res.Vector.Name),
		Severity: models.SeverityHigh,
		Confidence: models.ConfidenceHigh,
		Category: models.CategoryVulnerability,
		CWE: "CWE-22",
		OWASP: "A01:2021 - Broken Access Control",
		Target: target,
		URL: res.Vector.URL,
		Parameter: res.Vector.Name,
		Source: models.SourceActive,
		DetectionMethod: "path traversal probe: ../../../etc/passwd or win.ini content found in response",
		Evidence: models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact: "An attacker can read arbitrary files from the server filesystem, including configuration files, credentials, and source code.",
		Remediation: "Validate and canonicalize file paths. Reject any path containing traversal sequences. Use allowlists for permitted file access locations.",
		References: []string{"https://owasp.org/www-community/attacks/Path_Traversal", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"},
		FirstSeen: time.Now(),
	}
}
