package active

import (
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func platTech(name, category string, conf float64) models.Technology {
	return models.Technology{Name: name, Category: category, Confidence: conf}
}

func platFinding(id, url string, sev models.Severity) models.Finding {
	return models.Finding{ID: id, URL: url, Severity: sev, Target: "https://example.com"}
}

// Confident edge fingerprints suppress host-header vhost differentials.
func TestPlatformSuppressesHostHeaderOnEdge(t *testing.T) {
	in := []models.Finding{platFinding("active-host-header-1", "https://example.com/", models.SeverityHigh)}
	techs := []models.Technology{platTech("Vercel", "hosting", 0.9)}
	kept, warnings := platformFilter(in, techs)
	if len(kept) != 0 || len(warnings) != 1 {
		t.Fatalf("edge host-header must suppress to a warning, kept=%d warnings=%d", len(kept), len(warnings))
	}
	if !strings.Contains(warnings[0], "Vercel") {
		t.Fatalf("warning must name the platform: %q", warnings[0])
	}
}

// Weak body-text signals must not suppress (self-hosted stays fully tested).
func TestPlatformWeakSignalFailsOpen(t *testing.T) {
	in := []models.Finding{platFinding("active-host-header-1", "https://example.com/", models.SeverityHigh)}
	techs := []models.Technology{platTech("Vercel", "hosting", 0.65)}
	kept, warnings := platformFilter(in, techs)
	if len(kept) != 1 || len(warnings) != 0 {
		t.Fatalf("weak signal must not filter, kept=%d warnings=%d", len(kept), len(warnings))
	}
	if kept, warnings := platformFilter(in, nil); len(kept) != 1 || len(warnings) != 0 {
		t.Fatalf("empty stack must fail open, kept=%d warnings=%d", len(kept), len(warnings))
	}
}

// CDN demotes reflection-only cache candidates but keeps confirmed persistence.
func TestPlatformCacheCandidateDemotedOnCDN(t *testing.T) {
	cdn := []models.Technology{platTech("Cloudflare", "cdn", 0.9)}
	candidate := platFinding("active-cache-poison-1", "https://example.com/", models.SeverityMedium)
	kept, warnings := platformFilter([]models.Finding{candidate}, cdn)
	if len(kept) != 0 || len(warnings) != 1 {
		t.Fatalf("CDN candidate must demote, kept=%d warnings=%d", len(kept), len(warnings))
	}
	confirmed := platFinding("active-cache-poison-2", "https://example.com/", models.SeverityHigh)
	if kept, _ := platformFilter([]models.Finding{confirmed}, cdn); len(kept) != 1 {
		t.Fatal("confirmed persistence must survive on CDN")
	}
	// Non-platform findings pass through untouched.
	other := platFinding("active-sqli-1", "https://example.com/?q=1", models.SeverityHigh)
	if kept, _ := platformFilter([]models.Finding{other}, cdn); len(kept) != 1 {
		t.Fatal("unrelated findings must pass through")
	}
}
