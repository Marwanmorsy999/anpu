package active

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Canary / ghost prefix handling (P0 Ghost Core).
//
// By default all canaries contain the `anpu` substring so defenders can
// allowlist them via YARA / WAF rules (`anpu-` / `anpucache` / `anpucanary`).
// When --ghost is active the substring must disappear entirely so
// `ModSec @contains anpu` and similar signatures no longer trigger.
//
// GhostEnabled is set from cmd/anpu/scan.go when --ghost is passed.
// GhostCanaryPrefix controls the replacement prefix: default "" (pure
// random hex) when --ghost, "anpu" otherwise. Users may override via
// --ghost-canary-prefix.
var GhostEnabled bool
var GhostCanaryPrefix string = "anpu"

// SetGhost configures canary ghosting (called from scan flag handling).
func SetGhost(enabled bool, prefix string) {
	GhostEnabled = enabled
	if enabled {
		if prefix == "" {
			GhostCanaryPrefix = ""
		} else {
			GhostCanaryPrefix = prefix
		}
	} else {
		if prefix != "" {
			GhostCanaryPrefix = prefix
		} else {
			GhostCanaryPrefix = "anpu"
		}
	}
}

func effectivePrefix(defaultAnpu string) string {
	if GhostEnabled {
		if GhostCanaryPrefix == "" {
			return ""
		}
		return GhostCanaryPrefix
	}
	return defaultAnpu
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "deadbeef"
	}
	return hex.EncodeToString(b)
}

// XSSCanary returns the XSS injection payload and the detection substring.
// When ghost, both avoid the `anpu` substring and use a random id.
func XSSCanary() (payload, detect string) {
	if !GhostEnabled {
		return `anpu-xss-<b id="anpucanary">`, `<b id="anpucanary">`
	}
	prefix := effectivePrefix("anpu")
	if prefix != "" {
		id := prefix + randomHex(4)
		return fmt.Sprintf("%s-xss-<b id=\"%s\">", prefix, id), fmt.Sprintf(`<b id="%s">`, id)
	}
	id := randomHex(4)
	return fmt.Sprintf(`<b id="%s">`, id), fmt.Sprintf(`<b id="%s">`, id)
}

// XSSCanaryDetectSingle returns the single-quote variant detection.
func XSSCanaryDetectSingle(id string) string {
	return fmt.Sprintf(`<b id='%s'>`, id)
}

// CacheCanary returns a DNS/host-safe token for cache poisoning.
func CacheCanary() string {
	if !GhostEnabled {
		return "anpucache" + randomHex(6)
	}
	prefix := effectivePrefix("anpu")
	if prefix != "" {
		return prefix + "cache" + randomHex(6)
	}
	return randomHex(6)
}

// Fallback cache canary when rand fails — must also avoid anpu in ghost.
func cacheCanaryFallback() string {
	if GhostEnabled && GhostCanaryPrefix == "" {
		return "cache00deadbeef"
	}
	prefix := effectivePrefix("anpu")
	if prefix == "" {
		return "cache00"
	}
	return prefix + "cache00"
}

// HostCanary returns a host header canary domain.
func HostCanary() string {
	if !GhostEnabled {
		return "anpu-" + randomHex(6) + ".invalid"
	}
	prefix := effectivePrefix("anpu")
	if prefix != "" {
		return prefix + "-" + randomHex(6) + ".invalid"
	}
	// Pure random 12 hex when ghost with empty prefix (plan: random 12hex)
	return randomHex(6) + ".invalid"
}

// hostCanaryFallback for rand error.
func hostCanaryFallback() string {
	if GhostEnabled && GhostCanaryPrefix == "" {
		return randomHex(6) + ".invalid"
	}
	prefix := effectivePrefix("anpu")
	if prefix == "" {
		return "canary-fallback.invalid"
	}
	return prefix + "-canary-fallback.invalid"
}

// RedirectCanaryDomain returns the open-redirect canary domain.
func RedirectCanaryDomain() string {
	if !GhostEnabled {
		return `anpu-redirect-canary.invalid`
	}
	prefix := effectivePrefix("anpu")
	if prefix != "" {
		return prefix + "-redirect-canary.invalid"
	}
	return `ghost-redirect-canary.invalid`
}

// XXECanary returns the XXE entity name and payload id.
func XXECanary() (entity string, canaryValue string) {
	if !GhostEnabled {
		return "anpu-xxe-canary", "anpu-" + randomHex(4)
	}
	prefix := effectivePrefix("anpu")
	if prefix != "" {
		return prefix + "-xxe-canary", prefix + "-" + randomHex(4)
	}
	// No anpu substring at all.
	return "ghost-xxe-canary", randomHex(4)
}

// CmdCanary returns the shell-echo canary token for command injection
// probes. Non-ghost keeps `anpu-cmdi-canary` (YARA allowlist); ghost
// uses a prefix without any `anpu` substring.
func CmdCanary() string {
	if !GhostEnabled {
		return "anpu-cmdi-canary"
	}
	if p := effectivePrefix("anpu"); p != "" {
		return p + "-cmdi-canary"
	}
	return "ghost-cmdi-canary"
}

// CmdPayloads returns the shell-metacharacter payloads built around CmdCanary().
func CmdPayloads() []string {
	tok := CmdCanary()
	return []string{
		`|echo ` + tok,
		`||echo ` + tok,
		`;echo ` + tok,
		"`echo " + tok + "`",
	}
}

// CRLFCanaryHeader returns the canary header name for CRLF probes.
// Non-ghost keeps `X-Anpu-Crlf-Canary`; ghost avoids the substring.
func CRLFCanaryHeader() string {
	if !GhostEnabled {
		return "X-Anpu-Crlf-Canary"
	}
	if p := effectivePrefix("anpu"); p != "" {
		return "X-" + capitalize(p) + "-Crlf-Canary"
	}
	return "X-Ghost-Crlf-Canary"
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// SSICanary returns the SSI exec payload and its signal token.
func SSICanary() (payload, signal string) {
	tok := "anpu-ssi-canary"
	if GhostEnabled {
		if p := effectivePrefix("anpu"); p != "" {
			tok = p + "-ssi-canary"
		} else {
			tok = "ghost-ssi-canary"
		}
	}
	return `<!--#exec cmd="echo ` + tok + `" -->`, tok
}

// RFICanaryPath returns the canary path segment for RFI probes.
func RFICanaryPath() string {
	if !GhostEnabled {
		return "anpu-rfi-canary"
	}
	if p := effectivePrefix("anpu"); p != "" {
		return p + "-rfi-canary"
	}
	return "ghost-rfi-canary"
}

// HPPPollutedValue returns the second value injected for HPP probes.
func HPPPollutedValue() string {
	if !GhostEnabled {
		return "hpp_anpu2"
	}
	if p := effectivePrefix("anpu"); p != "" {
		return "hpp_" + p + "2"
	}
	return "hpp_ghost2"
}

// XXEEntity returns the DOCTYPE entity name for XXE probes.
func XXEEntity() string {
	if !GhostEnabled {
		return "anpu-xxe-canary"
	}
	if p := effectivePrefix("anpu"); p != "" {
		return p + "-xxe-canary"
	}
	return "ghost-xxe-canary"
}

// XXENonceValue returns the XXE canary value (entity content).
func XXENonceValue() string {
	if !GhostEnabled {
		return "anpu-" + randomHex(4)
	}
	if p := effectivePrefix("anpu"); p != "" {
		return p + "-" + randomHex(4)
	}
	return randomHex(4)
}

// XXERootTag returns the XML root/DOCTYPE name for XXE payloads.
func XXERootTag() string {
	if GhostEnabled {
		return "doc"
	}
	return "anpu"
}

// XXEOOBName returns the parameter-entity base name for XXE OOB probes.
// Non-ghost keeps `anpuoob` (see oob_test.go:246); ghost avoids it.
func XXEOOBName(nonce string) string {
	if !GhostEnabled {
		return "anpuoob" + nonce
	}
	if p := effectivePrefix("anpu"); p != "" {
		return p + "oob" + nonce
	}
	return "ghostoob" + nonce
}

// Log4ShellNonce returns the JNDI path nonce for Log4Shell probes.
func Log4ShellNonce() string {
	if !GhostEnabled {
		return "anpu" + randomHex(8)
	}
	if p := effectivePrefix("anpu"); p != "" {
		return p + randomHex(8)
	}
	return "ghost" + randomHex(8)
}

// DeserialPayload returns the Java serialization magic probe.
// Non-ghost keeps the historic base64 (TC_STRING "anpu"); ghost uses a
// neutral TC_STRING ("ghost-probe") so no `anpu` bytes cross the wire.
func DeserialPayload() string {
	if !GhostEnabled {
		return "rO0ABXQABWFucHU="
	}
	raw := append([]byte{0xac, 0xed, 0x00, 0x05, 0x74, 0x00, 0x0b}, []byte("ghost-probe")...)
	return base64.StdEncoding.EncodeToString(raw)
}

// UploadMarker returns the polyglot marker string for file upload probes.
func UploadMarker() string {
	if !GhostEnabled {
		return "anpu-polyglot"
	}
	if p := effectivePrefix("anpu"); p != "" {
		return p + "-polyglot"
	}
	return "ghost-polyglot"
}

// UploadFileName returns the polyglot file name for upload probes.
func UploadFileName() string {
	return UploadMarker() + ".gif.php"
}

// UploadPolyglot returns the polyglot file content for upload probes.
func UploadPolyglot() []byte {
	return []byte("GIF89a\n<?php echo '" + UploadMarker() + "'; ?>")
}

// SessionFixationCanary returns the pre-set session ID for fixation probes.
// Non-ghost keeps `ANPUFIX`; ghost avoids the substring (case-insensitive).
func SessionFixationCanary() string {
	if !GhostEnabled {
		return "ANPUFIX" + randomHexShort(4)
	}
	if p := effectivePrefix("anpu"); p != "" {
		return strings.ToUpper(p) + "FIX" + randomHexShort(4)
	}
	return "GHOSTFIX" + randomHexShort(4)
}

// OOBNoncePrefix returns prefix for OOB nonces.
func OOBNoncePrefix(base string) string {
	if GhostEnabled && GhostCanaryPrefix == "" {
		// Avoid anpu substring even in nonce category.
		// base like "anpussrf" -> "ssrf"+random
		trimmed := base
		if len(base) > 4 && base[:4] == "anpu" {
			trimmed = base[4:]
		}
		if trimmed == "" {
			trimmed = "oob"
		}
		return trimmed
	}
	prefix := effectivePrefix("anpu")
	if prefix != "" && len(base) > 4 && base[:4] != prefix {
		return prefix + base[4:]
	}
	return base
}
