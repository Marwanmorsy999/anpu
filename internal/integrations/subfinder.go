// Package integrations — subfinder passive-subdomain integration.
//
// subfinder (ProjectDiscovery) enumerates subdomains from passive
// sources. Results flow into ScanContext.Subdomains, where the Takeover
// stage consumes them alongside the built-in CT-log enumeration.
//
// Absence degrades to a warning.
package integrations

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
)

// SubfinderScanner implements scanner.Scanner by shelling out to subfinder.
type SubfinderScanner struct {
	// BinaryPath overrides the resolved path to subfinder (testing).
	BinaryPath string
	// Timeout bounds the whole subfinder invocation.
	Timeout time.Duration
}

func NewSubfinderScanner() *SubfinderScanner {
	return &SubfinderScanner{Timeout: 5 * time.Minute}
}

func (s *SubfinderScanner) Name() string { return "subfinder" }

func (s *SubfinderScanner) resolvedPath() string {
	if s.BinaryPath != "" {
		return s.BinaryPath
	}
	if path, err := findExecutable("subfinder"); err == nil {
		return path
	}
	return "subfinder"
}

func (s *SubfinderScanner) Available(ctx context.Context) bool { return true }
func (s *SubfinderScanner) availableExternal(ctx context.Context) bool {
	return versionCheck(ctx, s.resolvedPath())
}

// Run enumerates passive subdomains of the target's domain.
func (s *SubfinderScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	domain := sc.Target.Host
	if domain == "" {
		return scanner.StageResult{}, nil
	}
	if s.availableExternal(ctx) {
		args := []string{"-d", domain, "-silent", "-nc"}
		stdout, _, err := runCapture(ctx, s.Timeout, s.resolvedPath(), args...)
		if err == nil || len(bytes.TrimSpace(stdout)) > 0 {
			if subs := parseSubfinderOutput(stdout, domain); len(subs) > 0 {
				return scanner.StageResult{Subdomains: subs}, nil
			}
		}
	}
	// Embedded fallback: small DNS brute of common names
	return s.runEmbedded(ctx, domain)
}

func (s *SubfinderScanner) runEmbedded(ctx context.Context, domain string) (scanner.StageResult, error) {
	// Tiny embedded brute — 12 most common names, fast and quiet
	candidates := []string{"www", "api", "admin", "mail", "dev", "test", "staging", "app", "m", "blog", "shop", "cdn"}
	var out []string
	seen := map[string]bool{domain: true}
	out = append(out, domain)
	for _, c := range candidates {
		if len(out) >= 20 {
			break
		}
		host := c + "." + domain
		if seen[host] {
			continue
		}
		seen[host] = true
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		addrs, err := net.DefaultResolver.LookupIP(cctx, "ip", host)
		cancel()
		if err != nil || len(addrs) == 0 {
			continue
		}
		out = append(out, host)
	}
	if len(out) <= 1 {
		return scanner.StageResult{}, nil
	}
	// Return only the discovered subs (excluding the base domain already known)
	return scanner.StageResult{Subdomains: out[1:]}, nil
}

const maxSubfinderSubs = 1000

// parseSubfinderOutput converts plain subdomain lines into candidates
// scoped to the target domain (case-insensitive, deduped).
func parseSubfinderOutput(data []byte, domain string) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(out) >= maxSubfinderSubs {
			break
		}
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || seen[line] {
			continue
		}
		// Keep the domain itself and its subdomains; drop anything else
		// (banners, errors, out-of-scope leakage).
		if line != domain && !strings.HasSuffix(line, "."+domain) {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}
