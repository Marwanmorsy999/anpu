package models

// AuthzAnomalyKind classifies what kind of authorization anomaly was
// detected when comparing two identity contexts against the same endpoint.
type AuthzAnomalyKind string

const (
	// AnomalyAccessGranted means Context B received a successful response
	// (2xx) where Context A was denied (4xx).  Classic IDOR / privilege
	// escalation signal.
	AnomalyAccessGranted AuthzAnomalyKind = "access-granted"

	// AnomalyStatusDiffers means the two contexts received meaningfully
	// different HTTP status codes that suggest different access levels
	// (e.g. 200 vs 403, 200 vs 404-as-denial).
	AnomalyStatusDiffers AuthzAnomalyKind = "status-differs"

	// AnomalyBodyDiffers means both contexts received a 2xx but the
	// response bodies differ significantly — a signal that one context
	// sees data the other should not.
	AnomalyBodyDiffers AuthzAnomalyKind = "body-differs"

	// AnomalyRedirectDiffers means one context was redirected (e.g. to a
	// login page) while the other was not, suggesting access control via
	// redirect rather than a 403.
	AnomalyRedirectDiffers AuthzAnomalyKind = "redirect-differs"
)

// AuthzProbeResult captures one response in an authorization comparison pair.
type AuthzProbeResult struct {
	// Role is the identity label of the context that issued this request.
	Role string `json:"role"`
	// StatusCode is the HTTP status returned.
	StatusCode int `json:"status_code"`
	// FinalURL is the URL after following any redirects.
	FinalURL string `json:"final_url"`
	// BodyLength is the byte length of the (bounded) response body.
	BodyLength int `json:"body_length"`
	// BodySnippet is the first 256 bytes of the body, for evidence.
	// Truncated and safe to store — no credential values included.
	BodySnippet string `json:"body_snippet,omitempty"`
	// ContentType is the response Content-Type header value.
	ContentType string `json:"content_type,omitempty"`
}

// AuthzAnomaly is a single authorization discrepancy detected between two
// identity contexts probing the same endpoint.  It maps 1:1 to a Finding
// via authz.ToFinding().
type AuthzAnomaly struct {
	// URL is the endpoint that was probed.
	URL string `json:"url"`
	// Method is the HTTP method used (always GET in Phase 3).
	Method string `json:"method"`
	// Kind classifies the type of anomaly.
	Kind AuthzAnomalyKind `json:"kind"`
	// ContextA is the baseline (typically higher-privilege) response.
	ContextA AuthzProbeResult `json:"context_a"`
	// ContextB is the challenger (typically lower-privilege) response.
	ContextB AuthzProbeResult `json:"context_b"`
}
