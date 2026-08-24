package headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
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
