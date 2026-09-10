// Package oob provides opt-in out-of-band interaction confirmation via
// ProjectDiscovery's interactsh network (oast.pro et al.).
//
// A Session registers one correlation identity, collects DNS/HTTP/SMTP
// callbacks in the background, and lets rules wait for a nonce they
// embedded in a payload. This turns blind injection (SSRF, XXE,
// Log4Shell) from "injected, check your listener" into CONFIRMED.
//
// Privacy: enabling this sends callback metadata (source IP of the
// vulnerable server, nonce) to interactsh servers. It is strictly
// opt-in via --oob-interactsh and never used otherwise.
package oob

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	iclient "github.com/projectdiscovery/interactsh/pkg/client"
	iserver "github.com/projectdiscovery/interactsh/pkg/server"
)

// DefaultServer is used when no explicit interactsh server is given.
// The client library fans out across the public interactsh fleet.
const DefaultServer = ""

// Session is one interactsh correlation identity with background
// collection of its interactions.
type Session struct {
	client *iclient.Client
	host   string

	mu   sync.Mutex
	seen map[string]*iserver.Interaction // keyed by FullId
}

// NewSession registers a session and starts background polling.
// Call Close when the scan ends.
func NewSession(serverURL string) (*Session, error) {
	opts := *iclient.DefaultOptions
	if strings.TrimSpace(serverURL) != "" {
		opts.ServerURL = serverURL
	}
	c, err := iclient.New(&opts)
	if err != nil {
		return nil, fmt.Errorf("interactsh register: %w", err)
	}
	u := c.URL()
	if u == "" {
		_ = c.Close()
		return nil, fmt.Errorf("interactsh register: empty session URL")
	}
	s := &Session{client: c, host: hostOf(u), seen: map[string]*iserver.Interaction{}}
	go func() {
		// The interval is the poll cadence (not a total budget):
		// 5s is polite to the public fleet and fast enough for
		// per-probe confirmation windows. Close() stops it early.
		_ = c.StartPolling(5*time.Second, func(i *iserver.Interaction) {
			if i == nil {
				return
			}
			s.mu.Lock()
			s.seen[i.FullId] = i
			s.mu.Unlock()
		})
	}()
	return s, nil
}

// hostOf strips the scheme from a session URL.
func hostOf(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(lower, "://"); i >= 0 {
		lower = lower[i+3:]
	}
	if i := strings.IndexAny(lower, "/?#"); i >= 0 {
		lower = lower[:i]
	}
	return lower
}

// Host returns the session's interactsh domain (nonce goes left of it).
func (s *Session) Host() string { return s.host }

// CallbackURL builds the per-probe URL to inject: the nonce becomes a
// unique left-most label so callbacks attribute to one probe.
func (s *Session) CallbackURL(nonce string) string {
	return "https://" + nonce + "." + s.host + "/"
}

// WaitForCallback blocks up to timeout for any interaction whose full
// ID contains the nonce. Matching is case-insensitive: resolvers apply
// 0x20 case randomization, so the logged name rarely matches our case.
// Returns protocol and remote address on hit.
func (s *Session) WaitForCallback(nonce string, timeout time.Duration) (protocol, remote string, ok bool) {
	needle := strings.ToLower(nonce)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for id, in := range s.seen {
			if strings.Contains(strings.ToLower(id), needle) {
				protocol, remote = in.Protocol, in.RemoteAddress
				s.mu.Unlock()
				return protocol, remote, true
			}
		}
		s.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
	}
	return "", "", false
}

// Close stops polling and deregisters the session.
func (s *Session) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	_ = s.client.StopPolling()
	return s.client.Close()
}

// Nonce returns a DNS-safe random token, prefixed for attribution
// (prefix must already be lowercase alphanumeric).
func Nonce(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return prefix + "fallback01"
	}
	return prefix + hex.EncodeToString(b)
}

// Compile-time check: Session satisfies the callback contract the
// active rules program against (avoids an import cycle: active defines
// the interface, oob implements it).
var _ interface {
	Host() string
	CallbackURL(string) string
	WaitForCallback(string, time.Duration) (string, string, bool)
} = (*Session)(nil)
