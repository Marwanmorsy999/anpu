package findings

import (
	"sort"
	"strings"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// embeddedNucleiID and embeddedNucleiMethod mark the Nuclei stage's
// graceful-degradation finding (no external binary). It carries
// SourceNuclei but represents no Nuclei detection, so correlation
// excludes it: correlating against a placeholder would fabricate signal.
const (
	embeddedNucleiID     = "nuclei-embedded-info"
	embeddedNucleiMethod = "embedded nuclei fallback"
)

// isEmbeddedNucleiPlaceholder reports whether a finding is the Nuclei
// embedded-mode notice rather than a real template match. Only
// single-source Nuclei findings can be the placeholder: merged findings
// always carry SourceAggregation.
func isEmbeddedNucleiPlaceholder(f models.Finding) bool {
	if f.Source != models.SourceNuclei || len(f.MergedFrom) > 1 {
		return false
	}
	return f.ID == embeddedNucleiID ||
		strings.Contains(f.DetectionMethod, embeddedNucleiMethod)
}

// ComputeNucleiCorrelation partitions post-dedup findings by Nuclei
// overlap: seen by both sides, native-only, or Nuclei-only. Returns nil
// when no real Nuclei data participated (Nuclei off, or only the
// embedded fallback ran) so reports omit the section instead of showing
// an empty one.
func ComputeNucleiCorrelation(in []models.Finding) *models.NucleiCorrelation {
	nucleiPresent := false
	for _, f := range in {
		if isEmbeddedNucleiPlaceholder(f) {
			continue
		}
		if f.Source == models.SourceNuclei {
			nucleiPresent = true
			break
		}
		for _, ref := range f.MergedFrom {
			if ref.Source == models.SourceNuclei {
				nucleiPresent = true
				break
			}
		}
		if nucleiPresent {
			break
		}
	}
	if !nucleiPresent {
		return nil
	}
	out := &models.NucleiCorrelation{NucleiAvailable: true}
	for _, f := range in {
		if isEmbeddedNucleiPlaceholder(f) {
			continue
		}
		hasNuclei := f.Source == models.SourceNuclei
		hasNative := f.Source != models.SourceNuclei && f.Source != models.SourceAggregation
		for _, ref := range f.MergedFrom {
			switch ref.Source {
			case models.SourceNuclei:
				hasNuclei = true
			case models.SourceAggregation:
			default:
				hasNative = true
			}
		}
		switch {
		case hasNuclei && hasNative:
			out.Agreed = append(out.Agreed, f.ID)
		case hasNuclei:
			out.NucleiOnly = append(out.NucleiOnly, f.ID)
		default:
			out.AnpuOnly = append(out.AnpuOnly, f.ID)
		}
	}
	sort.Strings(out.Agreed)
	sort.Strings(out.AnpuOnly)
	sort.Strings(out.NucleiOnly)
	return out
}
