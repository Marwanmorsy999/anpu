package active

import (
	"strings"
)

// Adapt learns from server responses (429/403 encodings) and switches payload
// encodings / whitespace variants. It is the AI-adaptive payload layer for
// Master (ghost) — e.g., when WAF returns 403 for a payload, retry with
// /**/ whitespace, %2e encoding, or next Vault token.
//
// Encoding variants are applied inline by AdaptNext; callers iterate via
// AdaptNext when a response indicates blocking.

// AdaptNext returns the next encoding variant for a payload when the prior
// response was 403/429/WAF. It cycles whitespace, dot-encoding, and vault
// token substitution.
func AdaptNext(payload string, attempt int) string {
	if attempt <= 0 {
		return payload
	}
	variant := payload
	// Simple round-robin whitespace mutation
	switch attempt % 3 {
	case 1:
		variant = strings.ReplaceAll(variant, " ", "/**/")
	case 2:
		variant = strings.ReplaceAll(variant, ".", "%2e")
	}
	// On third attempt, also encode slash
	if attempt%4 == 3 {
		variant = strings.ReplaceAll(variant, "/", "%2F")
	}
	return variant
}

// AdaptFromStatus decides whether to adapt based on status code and body.
func AdaptFromStatus(status int, body string) bool {
	if status == 403 || status == 429 || status == 406 {
		return true
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "waf") || strings.Contains(lower, "blocked") || strings.Contains(lower, "forbidden")
}
