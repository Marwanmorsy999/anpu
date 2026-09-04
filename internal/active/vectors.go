package active

import (
	"net/url"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

// ExtractVectors returns all injectable InputVectors for the given endpoint.
// Phase 4 targets query parameters and path segments only — no body
// parameters, no headers (those are Phase 5 / API security).
//
// For each query parameter, one InputVector is produced with the
// parameter's original value.  For path segments that look like IDs or
// dynamic values, one InputVector is produced per segment.
func ExtractVectors(ep models.Endpoint) []models.InputVector {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil
	}

	var out []models.InputVector

	// --- Query parameters ---
	for name, values := range u.Query() {
		original := ""
		if len(values) > 0 {
			original = values[0]
		}
		out = append(out, models.InputVector{
			URL:           ep.URL,
			Kind:          models.VectorQueryParam,
			Name:          name,
			OriginalValue: original,
		})
	}

	// --- Path segments ---
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		// Only treat a segment as injectable when it looks dynamic:
		// contains digits, hyphens, underscores, or is short enough to
		// plausibly be an ID.  Static segments like "api", "v1", "users"
		// are skipped to keep the request count low.
		if isDynamicSegment(seg) {
			out = append(out, models.InputVector{
				URL:           ep.URL,
				Kind:          models.VectorPathSegment,
				Name:          seg,
				OriginalValue: seg,
			})
		}
	}

	return out
}

// isDynamicSegment returns true for path segments that look like they
// carry user-controlled values (IDs, slugs with digits, UUIDs, etc.).
func isDynamicSegment(seg string) bool {
	if len(seg) == 0 {
		return false
	}
	digits := 0
	for _, c := range seg {
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	// Treat as dynamic when: all digits, starts with digit, UUID-like
	// (contains hyphens + hex chars), or short alpha that looks like a slug.
	if digits == len(seg) {
		return true // pure numeric ID
	}
	if digits > 0 && strings.ContainsAny(seg, "-_") {
		return true // slug with numbers
	}
	// UUID pattern: 8-4-4-4-12
	if len(seg) == 36 && strings.Count(seg, "-") == 4 {
		return true
	}
	return false
}

// xmlContentTypes are the MIME types that signal an endpoint accepts XML bodies.
var xmlContentTypes = []string{
	"application/xml",
	"text/xml",
	"application/soap+xml",
	"application/xhtml+xml",
}

// isXMLContentType returns true when ct is a recognised XML MIME type.
// Matching is prefix-based so "application/xml; charset=utf-8" also matches.
func isXMLContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	for _, mime := range xmlContentTypes {
		if strings.HasPrefix(ct, mime) {
			return true
		}
	}
	return false
}

// ExtractXMLVectors returns a single VectorXMLBody for each endpoint that
// accepts an XML request body.  Detection is based on:
//
//  1. ep.Method is POST, PUT, or PATCH (XML bodies are write operations).
//  2. The endpoint was contributed by the API scanner with an XML content-type
//     encoded in its source tag ("api-xml-body").
//
// The Name field of the returned vector is set to the endpoint URL so that
// rules can use it as a stable, human-readable label in finding titles.
// OriginalValue is left empty — the rule supplies the full XML document.
func ExtractXMLVectors(eps []models.Endpoint) []models.InputVector {
	var out []models.InputVector
	seen := map[string]bool{}

	for _, ep := range eps {
		// Only POST/PUT/PATCH endpoints accept bodies.
		method := strings.ToUpper(ep.Method)
		if method != "POST" && method != "PUT" && method != "PATCH" {
			continue
		}

		// Deduplicate by URL — one XML probe per endpoint is sufficient.
		if seen[ep.URL] {
			continue
		}

		// Accept endpoints tagged as xml-body by the API scanner, or
		// any POST endpoint on paths that look like data-ingestion routes
		// (contain "xml", "soap", "feed", "import", "upload", "ingest").
		isXMLTagged := false
		for _, src := range ep.Sources {
			if src == "api-xml-body" {
				isXMLTagged = true
				break
			}
		}

		if !isXMLTagged {
			// Heuristic: path contains xml-suggesting words.
			lower := strings.ToLower(ep.URL)
			for _, hint := range []string{"xml", "soap", "feed", "import", "upload", "ingest", "document", "data"} {
				if strings.Contains(lower, hint) {
					isXMLTagged = true
					break
				}
			}
		}

		if !isXMLTagged {
			continue
		}

		seen[ep.URL] = true
		out = append(out, models.InputVector{
			URL:           ep.URL,
			Kind:          models.VectorXMLBody,
			Name:          ep.URL,
			OriginalValue: "",
		})
	}
	return out
}

// InjectQueryParam returns a new URL string with the named query parameter
// replaced by payload.  All other parameters are preserved unchanged.
func InjectQueryParam(rawURL, name, payload string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(name, payload)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// InjectPathSegment returns a new URL string with the named path segment
// replaced by payload.
func InjectPathSegment(rawURL, segment, payload string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	// Replace the first occurrence of the segment in the path.
	parts := strings.Split(u.Path, "/")
	replaced := false
	for i, p := range parts {
		if p == segment && !replaced {
			parts[i] = payload
			replaced = true
		}
	}
	u.Path = strings.Join(parts, "/")
	return u.String(), nil
}
