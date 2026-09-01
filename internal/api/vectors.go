package api

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

// ExtractAPIVectors converts the declared parameters of an APIEndpoint
// into InputVectors that the Phase 4 active rules can test.
//
// Phase 5 extension rules:
//   - Query and path params → existing VectorQueryParam / VectorPathSegment
//   - JSON body params → VectorJSONBody (new in Phase 5)
//   - Header params → VectorHeader (new in Phase 5, limited to schema-declared headers only)
//   - Cookie params → skipped (manipulating cookies without browser context is unreliable)
//
// The function only emits VectorHeader for headers that are explicitly
// declared in the schema — never for standard security headers such as
// Authorization, Cookie, or X-API-Key, to avoid leaking credential values.
func ExtractAPIVectors(ep models.APIEndpoint) []models.InputVector {
	var out []models.InputVector

	for _, p := range ep.Params {
		original := p.Example
		if original == "" {
			original = placeholderForType(p.Schema)
		}

		switch p.In {
		case models.APIParamInQuery:
			out = append(out, models.InputVector{
				URL:           ep.URL,
				Kind:          models.VectorQueryParam,
				Name:          p.Name,
				OriginalValue: original,
			})

		case models.APIParamInPath:
			out = append(out, models.InputVector{
				URL:           ep.URL,
				Kind:          models.VectorPathSegment,
				Name:          p.Name,
				OriginalValue: original,
			})

		case models.APIParamInBody:
			// JSON body injection: the Name encodes the full injection
			// path so rules can build a minimal JSON payload around it.
			out = append(out, models.InputVector{
				URL:           ep.URL,
				Kind:          models.VectorJSONBody,
				Name:          p.Name,
				OriginalValue: original,
			})

		case models.APIParamInHeader:
			// Only inject into non-sensitive schema-declared headers.
			if isSafeHeaderToProbe(p.Name) {
				out = append(out, models.InputVector{
					URL:           ep.URL,
					Kind:          models.VectorHeader,
					Name:          p.Name,
					OriginalValue: original,
				})
			}
		}
	}

	return out
}

// sensitiveHeaders is the deny-list of header names we never inject into,
// even if they appear in an API schema.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"x-auth-token":        true,
}

// isSafeHeaderToProbe returns true for schema-declared headers that are
// safe to use as injection points (i.e. not security-sensitive).
func isSafeHeaderToProbe(name string) bool {
	return !sensitiveHeaders[strings.ToLower(name)]
}

// placeholderForType returns a benign default value for a given JSON
// Schema type string.
func placeholderForType(schemaType string) string {
	switch strings.ToLower(schemaType) {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	case "array":
		return "[]"
	case "object":
		return "{}"
	default:
		return "test"
	}
}

// BuildJSONPayload constructs a minimal JSON request body with the named
// key set to payload, and all other keys from params set to their
// placeholder values.  This is the canonical way Phase 5 rules build
// POST bodies for JSON-body injection.
func BuildJSONPayload(params []models.APIParam, targetKey, payload string) (string, error) {
	m := make(map[string]interface{}, len(params))
	for _, p := range params {
		if p.In != models.APIParamInBody {
			continue
		}
		if p.Name == targetKey {
			m[p.Name] = payload
		} else {
			m[p.Name] = placeholderForType(p.Schema)
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("build JSON payload: %w", err)
	}
	return string(b), nil
}
