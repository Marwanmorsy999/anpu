// Package integrations — gates.go: runtime skip gates for wrapper
// stages. Unlike profile toggles (decided before the run), gates decide
// DURING the run using what the pipeline already learned: the fingerprinted
// stack, the discovered subdomain yield, the parameterized-URL corpus.
// A gated stage returns StageResult{Skipped} — rendered as a quiet [—]
// with the reason, never as a warning or a finding. All gates are
// fail-open: unknown or empty intel means the tool runs.
package integrations

import (
	"fmt"
	"strings"

	"github.com/anpu-project/anpu/internal/scanner"
)

// techGates maps wrapper tools to stack tokens; the tool runs unless the
// fingerprinted stack confidently disagrees. Tokens match substrings of
// "name + category" (e.g. "wordpress cms"), so cmseek's "cms" token
// matches any CMS while wpscan needs WordPress specifically.
var techGates = map[string][]string{
	"wpscan":     {"wordpress"},
	"droopescan": {"drupal"},
	"joomscan":   {"joomla"},
	"cmseek":     {"wordpress", "drupal", "joomla", "cms"},
}

// richSubdomainYield skips slow enumeration when natives already
// delivered a rich harvest (amass routinely burns its whole timeout
// for zero marginal hosts in that case).
const richSubdomainYield = 10

// gateReason returns a quiet-skip reason when a wrapper stage has
// nothing useful to do, or "" when it should run.
func gateReason(spec *ToolSpec, sc *scanner.ScanContext) string {
	if sc == nil {
		return ""
	}
	// Stack gate (fail-open on unknown stack).
	if tokens, ok := techGates[spec.Name]; ok && len(sc.Technologies) > 0 {
		matched := false
		for _, t := range sc.Technologies {
			hay := strings.ToLower(strings.TrimSpace(t.Name + " " + t.Category))
			for _, tok := range tokens {
				if strings.Contains(hay, tok) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return fmt.Sprintf("no %s signals in fingerprinted stack — skipping (unknown stack still runs)", strings.Join(tokens, "/"))
		}
	}
	// Yield gate: slow brute-force adds nothing on top of a rich harvest.
	if spec.Name == "amass" && len(sc.Subdomains) >= richSubdomainYield {
		return fmt.Sprintf("sufficient native subdomain yield (%d hosts) — skipping slow enumeration", len(sc.Subdomains))
	}
	// Corpus gate: reflection testers need at least one parameterized URL.
	if spec.RequiresParams && firstParamURL(sc) == "" {
		return "no parameterized URLs discovered to test"
	}
	return ""
}

// gatedSkip wraps gateReason for stage Run methods. The reason is bare
// (the pipeline renders the [—] marker itself).
func gatedSkip(spec *ToolSpec, sc *scanner.ScanContext) (scanner.StageResult, bool) {
	if reason := gateReason(spec, sc); reason != "" {
		return scanner.StageResult{Skipped: reason}, true
	}
	return scanner.StageResult{}, false
}
