// Package active implements ANPU's Phase 4 safe active testing engine.
//
// Architecture:
//
//	Attack Surface (endpoints)
//	        ↓
//	Input Vector Extraction
//	        ↓
//	Rule Engine (each rule: scope → payloads → probe → evidence → finding)
//	        ↓
//	Finding Normalization
//
// Design constraints enforced at every level:
//   - GET-only by default; rules may opt into query-param injection only.
//   - Every rule declares a SafetyLevel and a per-vector request budget.
//   - Rules are deterministic: same input → same payloads → reproducible.
//   - No rule sends credentials, PII, or destructive content.
//   - False-positive controls are required: confirmation check or
//     differential response analysis before emitting a finding.
//   - The --no-active flag disables the entire engine with zero network cost.
package active

import (
	"context"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// Rule is implemented by every active test rule.
type Rule interface {
	// ID returns the stable rule identifier (e.g. "xss-reflected").
	ID() models.ActiveRuleID

	// Name returns the human-readable rule name.
	Name() string

	// Safety returns this rule's safety classification.
	Safety() models.SafetyLevel

	// RequestBudget returns the maximum number of HTTP requests this rule
	// may make per input vector.  The engine enforces this limit.
	RequestBudget() int

	// Test probes one input vector and returns the result.
	// Implementations must:
	//   - Respect ctx cancellation.
	//   - Never exceed RequestBudget() requests.
	//   - Return Found=false when evidence is ambiguous.
	//   - Never include credential values in results.
	Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error)

	// ToFinding converts a positive result into a normalized Finding.
	// Only called when result.Found == true.
	ToFinding(result models.ActiveRuleResult, target string) models.Finding
}

// Registry holds the set of rules that will run against each input vector.
type Registry struct {
	rules []Rule
}

// DefaultRegistry returns all Phase 4 rules in priority order.
// Rules are ordered by signal quality: highest-confidence first.
func DefaultRegistry() *Registry {
	return &Registry{
		rules: []Rule{
			&xssRule{},
			&sqliRule{},
			&sstiRule{},
			&pathTraversalRule{},
			&openRedirectRule{},
			&crlfRule{},
			&ssrfRule{},
			&cmdInjectionRule{},
			&xxeRule{},
			&hostHeaderRule{},
			&nosqlRule{},
		},
	}
}

// Rules returns all registered rules.
func (r *Registry) Rules() []Rule { return r.rules }
