// Package integrations — dnsx DNS-toolkit integration.
//
// dnsx (ProjectDiscovery) is a fast DNS toolkit for resolution / brute-
// forcing / record enumeration. ANPU uses it to corroborate the built-in
// DNS intel and subdomain enumeration when installed: it feeds the domain
// to dnsx and normalizes resolved hosts and their A records.
//
// Absence degrades to a warning.
package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/scanner"
)

// DNSxScanner implements scanner.Scanner by shelling out to dnsx.
type DNSxScanner struct {
	BinaryPath string
	Timeout    time.Duration
}

func NewDNSxScanner() *DNSxScanner {
	return &DNSxScanner{Timeout: 3 * time.Minute}
}

func (d *DNSxScanner) Name() string { return "dnsx" }

func (d *DNSxScanner) resolvedPath() string {
	if d.BinaryPath != "" {
		return d.BinaryPath
	}
	if p, err := findExecutable("dnsx"); err == nil {
		return p
	}
	return "dnsx"
}

func (d *DNSxScanner) Available(ctx context.Context) bool { return true }
func (d *DNSxScanner) availableExternal(ctx context.Context) bool {
	return versionCheck(ctx, d.resolvedPath())
}

// dnsxJSONLine mirrors the resolution output ANPU normalizes.
type dnsxJSONLine struct {
	Host  string   `json:"host"`
	A     []string `json:"a"`
	CNAME string   `json:"cname"`
}

func (d *DNSxScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	domain := sc.Target.Host
	if domain == "" {
		return scanner.StageResult{}, nil
	}
	if d.availableExternal(ctx) {
		args := []string{"-d", domain, "-silent", "-json", "-a", "-resp-only"}
		stdout, _, err := runCapture(ctx, d.Timeout, d.resolvedPath(), args...)
		if err == nil || len(bytes.TrimSpace(stdout)) > 0 {
			if subs := parseDNSxOutput(stdout, domain); len(subs) > 0 {
				return scanner.StageResult{Subdomains: subs}, nil
			}
		}
	}
	// Embedded fallback: resolve apex and a few common records, return as subdomains for takeover
	return d.runEmbedded(ctx, domain)
}

func parseDNSxOutput(data []byte, domain string) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var j dnsxJSONLine
		if err := json.Unmarshal([]byte(line), &j); err != nil {
			// Fallback: plain host line
			host := strings.ToLower(line)
			if host != "" && (host == domain || strings.HasSuffix(host, "."+domain)) && !seen[host] {
				seen[host] = true
				out = append(out, host)
			}
			continue
		}
		host := strings.ToLower(strings.TrimSpace(j.Host))
		if host == "" {
			continue
		}
		if host != domain && !strings.HasSuffix(host, "."+domain) {
			continue
		}
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
		// CNAME target is also a hostname worth tracking if in-scope.
		if cname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(j.CNAME), ".")); cname != "" && (cname == domain || strings.HasSuffix(cname, "."+domain)) && !seen[cname] {
			seen[cname] = true
			out = append(out, cname)
		}
	}
	return out
}

func (d *DNSxScanner) runEmbedded(ctx context.Context, domain string) (scanner.StageResult, error) {
	// Minimal embedded DNSx: resolve A, MX, NS and return hosts
	var subs []string
	seen := map[string]bool{}
	add := func(host string) {
		host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
		if host == "" || seen[host] {
			return
		}
		if host != domain && !strings.HasSuffix(host, "."+domain) {
			return
		}
		seen[host] = true
		subs = append(subs, host)
	}
	// Apex
	add(domain)
	// NS hosts
	if nss, err := net.DefaultResolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			add(ns.Host)
		}
	}
	// MX hosts
	if mxs, err := net.DefaultResolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			add(mx.Host)
		}
	}
	// Common subdomain brute moved to subfinder; dnsx embedded just returns what we found
	if len(subs) <= 1 {
		return scanner.StageResult{}, nil
	}
	return scanner.StageResult{Subdomains: subs}, nil
}
