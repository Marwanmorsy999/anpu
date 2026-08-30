package auth

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestFromFlags_Anonymous(t *testing.T) {
	ctx, err := FromFlags("", nil, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.IsAuthenticated() {
		t.Error("expected anonymous context")
	}
	if ctx.EffectiveRole() != "anonymous" {
		t.Errorf("effective role = %q, want %q", ctx.EffectiveRole(), "anonymous")
	}
}

func TestFromFlags_Bearer(t *testing.T) {
	ctx, err := FromFlags("my-token", nil, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Method != models.AuthMethodBearer {
		t.Errorf("method = %q, want bearer", ctx.Method)
	}
	if ctx.BearerToken != "my-token" {
		t.Errorf("token = %q, want %q", ctx.BearerToken, "my-token")
	}
	if ctx.EffectiveRole() != "user" {
		t.Errorf("default role = %q, want user", ctx.EffectiveRole())
	}
}

func TestFromFlags_ExplicitRole(t *testing.T) {
	ctx, err := FromFlags("tok", nil, nil, "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.EffectiveRole() != "admin" {
		t.Errorf("role = %q, want admin", ctx.EffectiveRole())
	}
}

func TestFromFlags_Cookie(t *testing.T) {
	ctx, err := FromFlags("", []string{"session=abc", "csrf=xyz"}, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Method != models.AuthMethodCookie {
		t.Errorf("method = %q, want cookie", ctx.Method)
	}
	if len(ctx.Cookies) != 2 {
		t.Errorf("cookies len = %d, want 2", len(ctx.Cookies))
	}
}

func TestFromFlags_Header(t *testing.T) {
	ctx, err := FromFlags("", nil, []string{"X-Api-Key: secret"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Method != models.AuthMethodHeader {
		t.Errorf("method = %q, want header", ctx.Method)
	}
}

func TestFromFlags_MixingCredentialsIsError(t *testing.T) {
	_, err := FromFlags("tok", []string{"session=abc"}, nil, "")
	if err == nil {
		t.Error("expected error when mixing auth methods")
	}
}

func TestParseCookies(t *testing.T) {
	got := ParseCookies("session=abc; csrf=xyz")
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0] != "session=abc" {
		t.Errorf("[0] = %q, want %q", got[0], "session=abc")
	}
	if got[1] != "csrf=xyz" {
		t.Errorf("[1] = %q, want %q", got[1], "csrf=xyz")
	}
}

func TestParseCookies_Empty(t *testing.T) {
	if ParseCookies("") != nil {
		t.Error("empty input should return nil")
	}
}

func TestSummary_Anonymous(t *testing.T) {
	ctx := models.AuthContext{Method: models.AuthMethodNone}
	s := Summary(ctx)
	if s != "anonymous (no credentials)" {
		t.Errorf("summary = %q", s)
	}
}

func TestSummary_Bearer(t *testing.T) {
	ctx := models.AuthContext{
		Method:      models.AuthMethodBearer,
		BearerToken: "super-secret", // must NOT appear in summary
		Role:        "admin",
	}
	s := Summary(ctx)
	if s != "bearer token (role: admin)" {
		t.Errorf("summary = %q", s)
	}
	// Credential must not leak into summary.
	if containsString(s, "super-secret") {
		t.Error("credential value leaked into summary")
	}
}

func TestSummary_Cookie(t *testing.T) {
	ctx := models.AuthContext{
		Method:  models.AuthMethodCookie,
		Cookies: []string{"session=secret", "csrf=xyz"},
		Role:    "user",
	}
	s := Summary(ctx)
	if s != "2 cookie(s) (role: user)" {
		t.Errorf("summary = %q", s)
	}
}

func containsString(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && stringContains(s, sub))
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
