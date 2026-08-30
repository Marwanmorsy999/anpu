package models

import (
	"testing"
)

func TestAuthContextValidate(t *testing.T) {
	tests := []struct {
		name    string
		ctx     AuthContext
		wantErr bool
	}{
		{
			name:    "anonymous is valid",
			ctx:     AuthContext{Method: AuthMethodNone},
			wantErr: false,
		},
		{
			name:    "empty method is valid (anonymous)",
			ctx:     AuthContext{},
			wantErr: false,
		},
		{
			name:    "bearer with token is valid",
			ctx:     AuthContext{Method: AuthMethodBearer, BearerToken: "tok"},
			wantErr: false,
		},
		{
			name:    "bearer without token is invalid",
			ctx:     AuthContext{Method: AuthMethodBearer},
			wantErr: true,
		},
		{
			name:    "cookie with values is valid",
			ctx:     AuthContext{Method: AuthMethodCookie, Cookies: []string{"session=abc"}},
			wantErr: false,
		},
		{
			name:    "cookie without values is invalid",
			ctx:     AuthContext{Method: AuthMethodCookie},
			wantErr: true,
		},
		{
			name:    "header with values is valid",
			ctx:     AuthContext{Method: AuthMethodHeader, Headers: []string{"X-Api-Key: secret"}},
			wantErr: false,
		},
		{
			name:    "header without values is invalid",
			ctx:     AuthContext{Method: AuthMethodHeader},
			wantErr: true,
		},
		{
			name:    "unknown method is invalid",
			ctx:     AuthContext{Method: "magic"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ctx.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthContextRequestHeaders(t *testing.T) {
	t.Run("anonymous returns nil", func(t *testing.T) {
		ctx := AuthContext{Method: AuthMethodNone}
		if ctx.RequestHeaders() != nil {
			t.Error("expected nil headers for anonymous context")
		}
	})

	t.Run("bearer sets Authorization header", func(t *testing.T) {
		ctx := AuthContext{Method: AuthMethodBearer, BearerToken: "my-secret-token"}
		h := ctx.RequestHeaders()
		if got := h["Authorization"]; got != "Bearer my-secret-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer my-secret-token")
		}
	})

	t.Run("multiple cookies are joined", func(t *testing.T) {
		ctx := AuthContext{
			Method:  AuthMethodCookie,
			Cookies: []string{"session=abc", "csrf=xyz"},
		}
		h := ctx.RequestHeaders()
		want := "session=abc; csrf=xyz"
		if got := h["Cookie"]; got != want {
			t.Errorf("Cookie = %q, want %q", got, want)
		}
	})

	t.Run("custom header is parsed", func(t *testing.T) {
		ctx := AuthContext{
			Method:  AuthMethodHeader,
			Headers: []string{"X-Api-Key: super-secret"},
		}
		h := ctx.RequestHeaders()
		if got := h["X-Api-Key"]; got != "super-secret" {
			t.Errorf("X-Api-Key = %q, want %q", got, "super-secret")
		}
	})

	t.Run("custom header without leading space", func(t *testing.T) {
		ctx := AuthContext{
			Method:  AuthMethodHeader,
			Headers: []string{"Authorization:token"},
		}
		h := ctx.RequestHeaders()
		if got := h["Authorization"]; got != "token" {
			t.Errorf("Authorization = %q, want %q", got, "token")
		}
	})
}

func TestAuthContextEffectiveRole(t *testing.T) {
	if got := (AuthContext{}).EffectiveRole(); got != "anonymous" {
		t.Errorf("empty context effective role = %q, want %q", got, "anonymous")
	}
	if got := (AuthContext{Role: "admin"}).EffectiveRole(); got != "admin" {
		t.Errorf("explicit role = %q, want %q", got, "admin")
	}
}

func TestAuthContextIsAuthenticated(t *testing.T) {
	if (AuthContext{}).IsAuthenticated() {
		t.Error("empty context should not be authenticated")
	}
	if (AuthContext{Method: AuthMethodNone}).IsAuthenticated() {
		t.Error("none method should not be authenticated")
	}
	if !(AuthContext{Method: AuthMethodBearer, BearerToken: "t"}).IsAuthenticated() {
		t.Error("bearer context should be authenticated")
	}
}
