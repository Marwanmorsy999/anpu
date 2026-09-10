package active

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// OOBSession is the out-of-band callback contract the active rules
// program against. The concrete *oob.Session (interactsh) implements it;
// tests inject fakes. Defining the interface here (rather than importing
// internal/oob) keeps the active engine's dependency surface unchanged.
type OOBSession interface {
	// Host returns the interactsh domain nonces hang under.
	Host() string
	// CallbackURL builds the per-probe URL to inject.
	CallbackURL(nonce string) string
	// WaitForCallback blocks up to timeout for the nonce's callback.
	WaitForCallback(nonce string, timeout time.Duration) (protocol, remote string, ok bool)
}

// InteractSession, when non-nil, upgrades blind rules (SSRF, XXE,
// Log4Shell) from "injected" to CONFIRMED via observed callbacks.
// Set by scan.go when --oob-interactsh is passed; nil means OOB is off
// and rules behave exactly as before.
var InteractSession OOBSession

// oobWait is how long a rule waits for a callback after injecting.
// Server-side fetches are normally prompt; 12s bounds worst-case lag
// without stalling scans when nothing calls back.
const oobWait = 12 * time.Second

// oobNonce returns a DNS-safe random token for callback attribution.
// The prefix is ghost-normalized via OOBNoncePrefix so --ghost scans never
// emit the `anpu` substring in callback URLs (ModSec @contains evasion).
// Non-ghost prefixes (e.g. "anpussrf", "anpuxxe") are unchanged.
func oobNonce(prefix string) string {
	prefix = OOBNoncePrefix(prefix)
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return prefix + "fallback00"
	}
	return prefix + hex.EncodeToString(b)
}
