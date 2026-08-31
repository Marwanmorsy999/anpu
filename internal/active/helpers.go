package active

import "github.com/anpu-project/anpu/pkg/models"

// buildInjectedURL constructs a URL with the payload injected at the
// vector's location.  It is the single injection point for all rules,
// keeping injection logic consistent and auditable.
func buildInjectedURL(v models.InputVector, payload string) (string, error) {
	switch v.Kind {
	case models.VectorQueryParam:
		return InjectQueryParam(v.URL, v.Name, payload)
	case models.VectorPathSegment:
		return InjectPathSegment(v.URL, v.Name, payload)
	default:
		return InjectQueryParam(v.URL, v.Name, payload)
	}
}
