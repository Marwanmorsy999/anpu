package models

// ActiveRuleID is the stable identifier for an active test rule.
type ActiveRuleID string

// SafetyLevel classifies how cautious an active rule is.
// Only Benign and LowImpact rules ship in ANPU Phase 4.
// Destructive rules are intentionally out of scope.
type SafetyLevel string

const (
	// SafetyBenign — read-only probes that cannot modify state.
	SafetyBenign SafetyLevel = "benign"
	// SafetyLowImpact — may trigger server-side processing (e.g. a
	// reflected error) but cannot modify data or cause lasting side effects.
	SafetyLowImpact SafetyLevel = "low-impact"
)

// InputVector is one injectable location extracted from an endpoint.
// It describes exactly where a payload can be placed.
type InputVector struct {
	// URL is the full endpoint URL.
	URL string
	// Kind describes the injection point.
	Kind InputVectorKind
	// Name is the parameter / header / path-segment name.
	Name string
	// OriginalValue is the original value observed at this location.
	OriginalValue string
}

// InputVectorKind classifies an injection point.
type InputVectorKind string

const (
	VectorQueryParam  InputVectorKind = "query-param"
	VectorPathSegment InputVectorKind = "path-segment"
	VectorFragment    InputVectorKind = "fragment"
)

// ActiveRuleResult is the outcome of one rule run against one input vector.
type ActiveRuleResult struct {
	// RuleID identifies the rule that produced this result.
	RuleID ActiveRuleID
	// Vector is the injection point that was tested.
	Vector InputVector
	// Payload is the exact string that was injected (safe to log — no
	// credentials, no destructive content).
	Payload string
	// Evidence is the concrete response detail that confirmed the issue.
	Evidence string
	// Found is true when the rule detected a positive signal.
	Found bool
	// RequestsMade is how many HTTP requests this rule consumed.
	RequestsMade int
}

// Phase 5 additions: API-aware injection points.
const (
	// VectorJSONBody targets a named key inside a JSON request body.
	// Only emitted by the API scanner when a schema declares a body parameter.
	VectorJSONBody InputVectorKind = "json-body"
	// VectorHeader targets a named HTTP request header.
	// Used sparingly — only for headers declared in the API schema.
	VectorHeader InputVectorKind = "header"
)

// Phase 12 additions.
const (
	// VectorXMLBody targets an endpoint that accepts an XML request body.
	// Emitted by ExtractXMLVectors for POST/PUT endpoints whose Content-Type
	// is application/xml or text/xml (detected from API schema or response).
	// Only the xxeRule handles this kind.
	VectorXMLBody InputVectorKind = "xml-body"
)
