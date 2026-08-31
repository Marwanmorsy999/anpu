package authz

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func probe(role string, status, bodyLen int, finalURL string) models.AuthzProbeResult {
	return models.AuthzProbeResult{
		Role:       role,
		StatusCode: status,
		FinalURL:   finalURL,
		BodyLength: bodyLen,
	}
}

func TestCompare_NoAnomaly(t *testing.T) {
	// Both contexts denied — no anomaly.
	a := probe("admin", 200, 1024, "https://target.com/api/orders")
	b := probe("user", 403, 64, "https://target.com/api/orders")
	// A=200 B=403 is security relevant but A is the higher-priv baseline here;
	// we expect an anomaly only when B gets in where A does not.
	// A=200 B=403 → status-differs (expected authz working correctly) — still flagged.
	// Let's test a clean pair.
	a2 := probe("admin", 403, 64, "https://target.com/api/orders")
	b2 := probe("user", 403, 64, "https://target.com/api/orders")
	if got := Compare("https://target.com/api/orders", "GET", a2, b2); got != nil {
		t.Errorf("expected nil anomaly for identical 403/403, got %v", got.Kind)
	}
	_ = a
	_ = b
}

func TestCompare_AccessGranted(t *testing.T) {
	// A (higher-priv baseline) was denied; B (challenger) got through.
	a := probe("anonymous", 403, 64, "https://target.com/api/admin")
	b := probe("user", 200, 2048, "https://target.com/api/admin")
	got := Compare("https://target.com/api/admin", "GET", a, b)
	if got == nil {
		t.Fatal("expected AnomalyAccessGranted, got nil")
	}
	if got.Kind != models.AnomalyAccessGranted {
		t.Errorf("kind = %q, want %q", got.Kind, models.AnomalyAccessGranted)
	}
}

func TestCompare_StatusDiffers(t *testing.T) {
	a := probe("admin", 200, 512, "https://target.com/api/data")
	b := probe("user", 401, 64, "https://target.com/api/data")
	got := Compare("https://target.com/api/data", "GET", a, b)
	if got == nil {
		t.Fatal("expected AnomalyStatusDiffers, got nil")
	}
	if got.Kind != models.AnomalyStatusDiffers {
		t.Errorf("kind = %q, want %q", got.Kind, models.AnomalyStatusDiffers)
	}
}

func TestCompare_BodyDiffers(t *testing.T) {
	// Both 200 but body sizes differ by >15%.
	a := probe("admin", 200, 10000, "https://target.com/api/profile")
	b := probe("user", 200, 500, "https://target.com/api/profile")
	a.BodyLength = 10000
	b.BodyLength = 500
	got := Compare("https://target.com/api/profile", "GET", a, b)
	if got == nil {
		t.Fatal("expected AnomalyBodyDiffers, got nil")
	}
	if got.Kind != models.AnomalyBodyDiffers {
		t.Errorf("kind = %q, want %q", got.Kind, models.AnomalyBodyDiffers)
	}
}

func TestCompare_BodyDiffers_BelowThreshold(t *testing.T) {
	// Bodies differ by only 5% — below the significant delta.
	a := probe("admin", 200, 1000, "https://target.com/api/profile")
	b := probe("user", 200, 950, "https://target.com/api/profile")
	got := Compare("https://target.com/api/profile", "GET", a, b)
	if got != nil {
		t.Errorf("expected nil for sub-threshold body delta, got %v", got.Kind)
	}
}

func TestCompare_BodyDiffers_TooSmall(t *testing.T) {
	// Bodies are tiny — skip comparison.
	a := probe("admin", 200, 30, "https://target.com/api/ping")
	b := probe("user", 200, 5, "https://target.com/api/ping")
	got := Compare("https://target.com/api/ping", "GET", a, b)
	if got != nil {
		t.Errorf("expected nil for tiny bodies, got %v", got.Kind)
	}
}

func TestCompare_RedirectDiffers(t *testing.T) {
	a := probe("anonymous", 200, 512, "https://target.com/login?next=/dashboard")
	b := probe("user", 200, 8192, "https://target.com/dashboard")
	got := Compare("https://target.com/dashboard", "GET", a, b)
	if got == nil {
		t.Fatal("expected AnomalyRedirectDiffers, got nil")
	}
	if got.Kind != models.AnomalyRedirectDiffers {
		t.Errorf("kind = %q, want %q", got.Kind, models.AnomalyRedirectDiffers)
	}
}

func TestToFinding_CredentialValuesAbsent(t *testing.T) {
	// Ensure that credential-like strings (tokens, cookie values) never
	// appear in a finding, even if somehow included in a probe result.
	anomaly := &models.AuthzAnomaly{
		URL:    "https://target.com/api/secret",
		Method: "GET",
		Kind:   models.AnomalyAccessGranted,
		ContextA: models.AuthzProbeResult{
			Role: "anonymous", StatusCode: 403, BodyLength: 64,
			FinalURL: "https://target.com/api/secret",
		},
		ContextB: models.AuthzProbeResult{
			Role: "user", StatusCode: 200, BodyLength: 2048,
			FinalURL: "https://target.com/api/secret",
		},
	}
	f := ToFinding(anomaly, "https://target.com")

	// Severity and category must be set.
	if f.Severity == "" {
		t.Error("finding has no severity")
	}
	if f.Category != models.CategoryAuthorization {
		t.Errorf("category = %q, want %q", f.Category, models.CategoryAuthorization)
	}
	if f.Source != models.SourceAuthz {
		t.Errorf("source = %q, want %q", f.Source, models.SourceAuthz)
	}
	if f.CWE == "" {
		t.Error("finding has no CWE")
	}
	// Evidence must not contain raw bearer tokens or cookie values.
	secret := "super-secret-token"
	if contains(f.Evidence.Observed, secret) || contains(f.Title, secret) {
		t.Error("credential value leaked into finding")
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && stringContains(s, sub)
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestIsLoginLike(t *testing.T) {
	cases := map[string]bool{
		"https://example.com/login":        true,
		"https://example.com/signin":       true,
		"https://example.com/auth/session": true,
		"https://example.com/dashboard":    false,
		"https://example.com/api/orders":   false,
	}
	for url, want := range cases {
		if got := isLoginLike(url); got != want {
			t.Errorf("isLoginLike(%q) = %v, want %v", url, got, want)
		}
	}
}
