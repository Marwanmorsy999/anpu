package findings

import "github.com/anpu-project/anpu/pkg/models"

// FilterByConfidence removes findings whose Confidence rank falls below
// the minimum. When min is empty ("") the input slice is returned
// unchanged (zero allocation, no copy).
//
// Filtered findings are excluded from reports and CI gates but are
// counted so the terminal summary can surface how many were suppressed.
func FilterByConfidence(in []models.Finding, min models.Confidence) (kept, suppressed []models.Finding) {
	if min == "" {
		return in, nil
	}
	minRank := min.Rank()
	for _, f := range in {
		if f.Confidence.Rank() >= minRank {
			kept = append(kept, f)
		} else {
			suppressed = append(suppressed, f)
		}
	}
	return kept, suppressed
}

// ParseMinConfidence validates and parses a --min-confidence flag value.
// An empty string or "none" disables the filter (returns "", nil).
// Returns an error for unrecognised values.
func ParseMinConfidence(raw string) (models.Confidence, error) {
	if raw == "" || raw == "none" {
		return "", nil
	}
	c := models.Confidence(raw)
	if !c.Valid() {
		return "", &badConfidenceError{raw}
	}
	return c, nil
}

type badConfidenceError struct{ val string }

func (e *badConfidenceError) Error() string {
	return "invalid --min-confidence " + `"` + e.val + `"` +
		": must be one of none, low, medium, high, confirmed"
}
