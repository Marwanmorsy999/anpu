// Package auth handles ANPU's authentication context: loading credentials
// from CLI flags or YAML config, validating them, and applying them to
// outgoing HTTP requests.
//
// Design rules:
//   - Authentication is always opt-in and explicit.  No guessing, no
//     brute-force, no credential derivation.
//   - Credentials never appear in logs or finding evidence.
//   - The anonymous context is the default and requires no configuration.
package auth

import (
	"fmt"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

// FromFlags constructs an AuthContext from the raw CLI flag values passed
// by the scan command.  Exactly one of the three credential flags may be
// non-empty; mixing them is an error.
//
// Flag conventions:
//
//	--auth-token  <value>           → bearer token
//	--auth-cookie <name=value> ...  → one or more cookie pairs (flag repeatable)
//	--auth-header <Name: Value> ... → one or more custom headers (flag repeatable)
//	--auth-role   <label>           → optional role name (defaults to "anonymous"
//	                                  or "user" when credentials are present)
func FromFlags(token string, cookies, headers []string, role string) (models.AuthContext, error) {
	// Count how many credential types are active.
	active := 0
	if token != "" {
		active++
	}
	if len(cookies) > 0 {
		active++
	}
	if len(headers) > 0 {
		active++
	}

	if active > 1 {
		return models.AuthContext{}, fmt.Errorf(
			"at most one auth method may be specified at a time (--auth-token, --auth-cookie, --auth-header)",
		)
	}

	ctx := models.AuthContext{}

	switch {
	case token != "":
		ctx.Method = models.AuthMethodBearer
		ctx.BearerToken = token
		if role == "" {
			role = "user"
		}
	case len(cookies) > 0:
		ctx.Method = models.AuthMethodCookie
		ctx.Cookies = cookies
		if role == "" {
			role = "user"
		}
	case len(headers) > 0:
		ctx.Method = models.AuthMethodHeader
		ctx.Headers = headers
		if role == "" {
			role = "user"
		}
	default:
		ctx.Method = models.AuthMethodNone
		if role == "" {
			role = "anonymous"
		}
	}

	ctx.Role = models.AuthRole(role)

	if err := ctx.Validate(); err != nil {
		return models.AuthContext{}, err
	}
	return ctx, nil
}

// ParseCookies splits a raw "name=value; name2=value2" string (as you
// might paste from DevTools) into individual "name=value" entries
// suitable for AuthContext.Cookies.  It also accepts a pre-split slice
// through the repeatable flag — this helper is for the single-string
// form only.
func ParseCookies(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// RedactedRole returns the role label for display in terminal output and
// scan metadata.  It never exposes credential values.
func RedactedRole(ctx models.AuthContext) string {
	return string(ctx.EffectiveRole())
}

// Summary returns a short, credential-free description of the auth
// context for terminal output (e.g. "bearer token (role: admin)").
func Summary(ctx models.AuthContext) string {
	if !ctx.IsAuthenticated() {
		return "anonymous (no credentials)"
	}
	role := string(ctx.EffectiveRole())
	switch ctx.Method {
	case models.AuthMethodBearer:
		return fmt.Sprintf("bearer token (role: %s)", role)
	case models.AuthMethodCookie:
		return fmt.Sprintf("%d cookie(s) (role: %s)", len(ctx.Cookies), role)
	case models.AuthMethodHeader:
		return fmt.Sprintf("%d custom header(s) (role: %s)", len(ctx.Headers), role)
	default:
		return fmt.Sprintf("method=%s (role: %s)", ctx.Method, role)
	}
}
