// Package scope enforces an operator-supplied target allowlist with a
// hard stop: when --scope-file is set, any target not on the list aborts
// before a single packet is sent. Empty scope file path = allow-all
// (current behavior, unchanged).
//
// File format: one hostname per line, `#` comments and blank lines
// ignored, case-insensitive, optional :port suffix allowed. A bare
// hostname matches any port; an entry with a port matches only it.
// Subdomain wildcards (`*.example.com`) match one or more labels.
package scope

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Allowlist is a parsed scope file.
type Allowlist struct {
	entries []string
}

// LoadFile parses a scope file. Missing path returns (nil, nil) so
// callers treat "no scope file" as allow-all.
func LoadFile(path string) (*Allowlist, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
	if err != nil {
		return nil, fmt.Errorf("reading scope file: %w", err)
	}
	defer func() { _ = f.Close() }()
	var entries []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSuffix(line, ".")
		entries = append(entries, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading scope file: %w", err)
	}
	return &Allowlist{entries: entries}, nil
}

// Allows reports whether host[:port] is in scope. A nil allowlist
// allows everything (no --scope-file given).
func (a *Allowlist) Allows(host, port string) bool {
	if a == nil {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	port = strings.TrimSpace(port)
	for _, e := range a.entries {
		if matchEntry(e, host, port) {
			return true
		}
	}
	return false
}

func matchEntry(entry, host, port string) bool {
	eHost, ePort := splitHostPort(entry)
	if ePort != "" && port != "" && ePort != port {
		return false
	}
	if strings.HasPrefix(eHost, "*.") {
		base := strings.TrimPrefix(eHost, "*.")
		if host == base {
			return true
		}
		return strings.HasSuffix(host, "."+base)
	}
	return host == eHost
}

func splitHostPort(s string) (host, port string) {
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i:], "]") {
		// Avoid splitting bare IPv6 literals (more than one colon).
		if strings.Count(s, ":") == 1 {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

// Enforce is the hard stop: nil allowlist passes; anything not listed
// returns a fatal error naming the scope file.
func Enforce(a *Allowlist, scopePath, host, port string) error {
	if a == nil {
		return nil
	}
	if a.Allows(host, port) {
		return nil
	}
	disp := host
	if port != "" {
		disp = host + ":" + port
	}
	return fmt.Errorf("target %s is not in scope file %s — refusing to scan (hard stop)", disp, scopePath)
}

// RedirectAlias reports the redirect-observed host when finalRaw sits on
// a different hostname under the SAME registrable domain as targetRaw
// (the classic apex → www hop). The alias joins the in-memory scan scope
// so crawlers and stage host-gates treat it as the same site instead of
// starving on empty discovery. Cross-domain hops never expand scope.
func RedirectAlias(targetRaw, finalRaw string) (string, bool) {
	tu, err := url.Parse(strings.TrimSpace(targetRaw))
	if err != nil || tu.Hostname() == "" {
		return "", false
	}
	fu, err := url.Parse(strings.TrimSpace(finalRaw))
	if err != nil || fu.Hostname() == "" {
		return "", false
	}
	th := strings.ToLower(strings.TrimSuffix(tu.Hostname(), "."))
	fh := strings.ToLower(strings.TrimSuffix(fu.Hostname(), "."))
	if th == "" || fh == "" || strings.EqualFold(th, fh) {
		return "", false
	}
	if registrableBase(th) == "" || registrableBase(th) != registrableBase(fh) {
		return "", false
	}
	return fh, true
}

// registrableBase returns the effective-TLD-plus-one for hostnames so
// apex and www compare equal; IPs and single labels return verbatim.
func registrableBase(host string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return h
	}
	if net.ParseIP(strings.Trim(h, "[]")) != nil {
		return h
	}
	if base, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil && base != "" {
		return base
	}
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
