package models

import "fmt"

// AuthRole names the identity a scan context runs as.  Roles are user-defined
// labels (e.g. "anonymous", "user", "admin") so ANPU can distinguish findings
// that only manifest under a particular identity.
type AuthRole string

// AuthMethod is the mechanism used to authenticate requests.
type AuthMethod string

const (
	AuthMethodNone   AuthMethod = "none"
	AuthMethodBearer AuthMethod = "bearer"
	AuthMethodCookie AuthMethod = "cookie"
	AuthMethodHeader AuthMethod = "header"
)

// AuthContext describes a single scan identity.  It is intentionally
// credential-forward: ANPU never guesses, brute-forces, or derives
// credentials — every value here must be supplied explicitly by the
// operator.
//
// Authentication is opt-in.  An empty AuthContext (Method == AuthMethodNone)
// means the scan runs as an anonymous user.  That is the safe default.
type AuthContext struct {
	// Role is a human-readable label for this identity (e.g. "admin",
	// "user", "anonymous").  Defaults to "anonymous" when Method is None.
	Role AuthRole `yaml:"role" json:"role"`

	// Method selects the credential mechanism.
	Method AuthMethod `yaml:"method" json:"method"`

	// BearerToken is used when Method == AuthMethodBearer.
	// The value is sent as:  Authorization: Bearer <token>
	BearerToken string `yaml:"bearer_token" json:"bearer_token,omitempty"`

	// Cookies is a list of name=value pairs used when Method ==
	// AuthMethodCookie.  Each pair is sent in a single Cookie header.
	Cookies []string `yaml:"cookies" json:"cookies,omitempty"`

	// Headers is a list of "Name: Value" strings used when Method ==
	// AuthMethodHeader.  They are merged into every outgoing request.
	Headers []string `yaml:"headers" json:"headers,omitempty"`
}

// IsAuthenticated reports whether this context carries any credentials.
func (a AuthContext) IsAuthenticated() bool {
	return a.Method != AuthMethodNone && a.Method != ""
}

// EffectiveRole returns the role label, defaulting to "anonymous".
func (a AuthContext) EffectiveRole() AuthRole {
	if a.Role == "" {
		return AuthRole("anonymous")
	}
	return a.Role
}

// Validate reports whether the AuthContext is internally consistent.
// An anonymous context always passes.  A credentialed context must have
// the right fields populated for its method.
func (a AuthContext) Validate() error {
	switch a.Method {
	case "", AuthMethodNone:
		return nil
	case AuthMethodBearer:
		if a.BearerToken == "" {
			return fmt.Errorf("auth method %q requires bearer_token", a.Method)
		}
	case AuthMethodCookie:
		if len(a.Cookies) == 0 {
			return fmt.Errorf("auth method %q requires at least one cookie", a.Method)
		}
	case AuthMethodHeader:
		if len(a.Headers) == 0 {
			return fmt.Errorf("auth method %q requires at least one header", a.Method)
		}
	default:
		return fmt.Errorf("unknown auth method %q: must be none, bearer, cookie, or header", a.Method)
	}
	return nil
}

// RequestHeaders returns the map of HTTP headers that should be merged
// into every authenticated request for this context.  Returns nil for
// anonymous contexts.
func (a AuthContext) RequestHeaders() map[string]string {
	if !a.IsAuthenticated() {
		return nil
	}

	out := make(map[string]string)

	switch a.Method {
	case AuthMethodBearer:
		out["Authorization"] = "Bearer " + a.BearerToken

	case AuthMethodCookie:
		// Merge all name=value pairs into one Cookie header.
		cookie := ""
		for i, c := range a.Cookies {
			if i > 0 {
				cookie += "; "
			}
			cookie += c
		}
		out["Cookie"] = cookie

	case AuthMethodHeader:
		// Each entry is expected to be "Name: Value".
		for _, h := range a.Headers {
			for i := 0; i < len(h); i++ {
				if h[i] == ':' {
					name := h[:i]
					value := ""
					if i+1 < len(h) {
						value = h[i+1:]
					}
					// Trim a single leading space from value per HTTP convention.
					if len(value) > 0 && value[0] == ' ' {
						value = value[1:]
					}
					if name != "" {
						out[name] = value
					}
					break
				}
			}
		}
	}

	return out
}
