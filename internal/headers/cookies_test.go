package headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

func TestCookieAnalyzer_FlagsMissingHttpOnlyAndSameSite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "abcdef1234567890"})
		w.WriteHeader(200)
	}))
	defer srv.Close()

	a := NewCookieAnalyzer(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := a.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasFindingID(res.Findings, "cookie-missing-httponly-sessionid") {
		t.Error("expected missing-httponly finding")
	}
	if !hasFindingID(res.Findings, "cookie-samesite-sessionid") {
		t.Error("expected samesite finding")
	}
}

func TestCookieAnalyzer_SecureFlagOnHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "abcdef1234567890", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		w.WriteHeader(200)
	}))
	defer srv.Close()

	a := NewCookieAnalyzer(insecureTestClient())
	res, err := a.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasFindingID(res.Findings, "cookie-missing-secure-sessionid") {
		t.Error("expected missing-secure finding since cookie lacks Secure on an HTTPS response")
	}
}

func TestCookieAnalyzer_NoCookiesObserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	a := NewCookieAnalyzer(anpuhttp.NewClientWithLocalNetworkAllowed(true))
	res, err := a.Run(context.Background(), newTestContext(t, srv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasFindingID(res.Findings, "cookies-none-observed") {
		t.Error("expected cookies-none-observed finding")
	}
}

// insecureTestClient returns a client whose transport skips TLS
// verification, since httptest.NewTLSServer uses a self-signed cert.
func insecureTestClient() *anpuhttp.Client {
	return anpuhttp.NewInsecureClientWithLocalNetworkAllowed(true)
}

func TestIsSessionCookieName(t *testing.T) {
	hits := []string{"session", "SESSIONID", "auth_token", "jwt", "user_sid", "login_token", "csrf"}
	for _, name := range hits {
		if !isSessionCookieName(name) {
			t.Errorf("isSessionCookieName(%q) = false, want true", name)
		}
	}
	misses := []string{"theme", "lang", "currency", "cookieconsent", "utm_source"}
	for _, name := range misses {
		if isSessionCookieName(name) {
			t.Errorf("isSessionCookieName(%q) = true, want false", name)
		}
	}
}

func TestHostPrefix_MissingSecure(t *testing.T) {
	c := &http.Cookie{Name: "__Host-session", Value: "abc", Secure: false, Path: "/"}
	findings := analyzeCookie(c, "https://example.com", "https://example.com", true)
	found := false
	for _, f := range findings {
		if f.ID == "cookie-host-prefix-missing-secure---host-session" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected host-prefix-missing-secure finding, got ids: %v", cookieIDs(findings))
	}
}

func TestHostPrefix_WithDomain(t *testing.T) {
	c := &http.Cookie{Name: "__Host-session", Value: "abc", Secure: true, Domain: "example.com", Path: "/"}
	findings := analyzeCookie(c, "https://example.com", "https://example.com", true)
	found := false
	for _, f := range findings {
		if f.ID == "cookie-host-prefix-has-domain---host-session" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected host-prefix-has-domain finding, got ids: %v", cookieIDs(findings))
	}
}

func TestSecurePrefix_MissingSecure(t *testing.T) {
	c := &http.Cookie{Name: "__Secure-auth", Value: "abc", Secure: false}
	findings := analyzeCookie(c, "https://example.com", "https://example.com", true)
	found := false
	for _, f := range findings {
		if f.ID == "cookie-secure-prefix-missing-secure---secure-auth" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected secure-prefix-missing-secure finding, got ids: %v", cookieIDs(findings))
	}
}

func TestSessionCookie_ElevatedSameSiteSeverity(t *testing.T) {
	c := &http.Cookie{Name: "session_id", Value: "abc", HttpOnly: true, Secure: true, SameSite: http.SameSiteDefaultMode}
	findings := analyzeCookie(c, "https://example.com", "https://example.com", true)
	for _, f := range findings {
		if f.ID == "cookie-samesite-session-id" {
			if f.Severity != models.SeverityMedium {
				t.Errorf("session cookie SameSite severity = %q, want Medium", f.Severity)
			}
			return
		}
	}
	t.Error("expected cookie-samesite-session-id finding")
}

func cookieIDs(findings []models.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return ids
}
