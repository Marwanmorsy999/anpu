// Package params classifies query parameters found on discovered
// endpoints into attacker-interest buckets (gf-style): sqli, xss, ssrf,
// idor, redirect, lfi, rce, ssti.
//
// It is fully passive — no requests are made — so it runs on every
// profile, including safe. Output is a single informational finding that
// tells the operator (and future dalfox/sqlmap integrations) exactly
// which URLs deserve focused injection testing.
package params

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Scanner implements scanner.Scanner for parameter classification.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string                     { return "params" }
func (s *Scanner) Available(_ context.Context) bool { return true }

// buckets maps a lower-cased parameter name to interest buckets.
// Exact match first; well-known prefixed variants (user_id, orderID…)
// resolve through baseForms below.
var buckets = map[string][]string{
	// SQL injection prone
	"id": {"sqli", "idor"}, "uid": {"sqli", "idor"}, "user": {"sqli"},
	"account": {"sqli"}, "number": {"sqli"}, "order": {"sqli", "idor"},
	"invoice": {"sqli", "idor"}, "report": {"sqli"}, "page": {"sqli", "lfi"},
	"row": {"sqli"}, "col": {"sqli"}, "sort": {"sqli"}, "order_by": {"sqli"},
	// Cross-site scripting prone
	"q": {"sqli", "xss"}, "query": {"sqli", "xss"}, "s": {"xss"},
	"search": {"sqli", "xss"}, "keyword": {"sqli", "xss"}, "name": {"xss", "ssti"},
	"title": {"xss"}, "message": {"xss", "ssti"}, "msg": {"xss"},
	"comment": {"xss"}, "text": {"xss"}, "description": {"xss"},
	"input": {"xss"}, "value": {"xss"}, "data": {"xss"},
	// SSRF prone
	"url": {"ssrf", "redirect"}, "uri": {"ssrf"}, "link": {"ssrf"},
	"src": {"ssrf"}, "source": {"ssrf"}, "webhook": {"ssrf"},
	"endpoint": {"ssrf"}, "host": {"ssrf"}, "proxy": {"ssrf"},
	"fetch": {"ssrf"}, "load": {"ssrf", "lfi"}, "file": {"ssrf", "lfi", "sqli"},
	"path": {"ssrf", "lfi"}, "dest": {"ssrf", "redirect"}, "domain": {"ssrf"},
	"site": {"ssrf"}, "feed": {"ssrf"}, "api": {"ssrf"},
	// IDOR prone
	"doc": {"idor", "lfi"}, "document": {"idor", "lfi"}, "key": {"idor"},
	"uuid": {"idor"}, "guid": {"idor"}, "token": {"idor"},
	"order_id": {"sqli", "idor"}, "user_id": {"sqli", "idor"},
	"account_id": {"sqli", "idor"}, "file_id": {"sqli", "idor", "lfi"},
	// Open redirect prone
	"redirect": {"redirect", "ssrf"}, "redir": {"redirect"},
	"next": {"redirect"}, "return": {"redirect"}, "returnurl": {"redirect"},
	"return_url": {"redirect"}, "continue": {"redirect"},
	"destination": {"redirect"}, "target": {"redirect", "ssrf"},
	"r": {"redirect"}, "u": {"redirect"}, "to": {"redirect"},
	"callback": {"redirect", "ssrf"}, "ref": {"redirect"},
	// LFI / path traversal prone
	"folder": {"lfi"}, "pg": {"lfi"}, "style": {"lfi"}, "pdf": {"lfi"},
	"template": {"lfi", "ssti", "rce"},
	"lang":     {"lfi"}, "language": {"lfi"}, "cat": {"lfi"}, "include": {"lfi", "rce"},
	// RCE prone
	"cmd": {"rce"}, "exec": {"rce"}, "command": {"rce"}, "execute": {"rce"},
	"ping": {"rce"}, "code": {"rce"}, "func": {"rce"}, "arg": {"rce"},
	"option": {"rce"}, "process": {"rce"}, "step": {"rce"}, "module": {"rce"},
	"payload": {"rce"}, "run": {"rce"},
	// SSTI prone
	"preview": {"ssti", "xss"}, "view": {"ssti", "lfi"}, "greeting": {"ssti"},
}

// baseForms strips common suffixes/digits so userId, orderID,
// file_path and page2 still classify.
func baseForms(name string) []string {
	// Split camelCase humps first: userId → user_id, orderID → order_i_d.
	var b strings.Builder
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	name = strings.ToLower(b.String())
	forms := []string{name}
	compact := strings.ReplaceAll(name, "_", "")
	if compact != name {
		forms = append(forms, compact)
	}
	for _, f := range append([]string{name}, compact) {
		for _, suf := range []string{"_id", "id", "_path", "path", "_url", "url", "_name", "name", "[]"} {
			if strings.HasSuffix(f, suf) && len(f) > len(suf)+1 {
				forms = append(forms, strings.TrimSuffix(f, suf))
			}
		}
		// trailing digits: page2, id1
		if t := strings.TrimRight(f, "0123456789"); t != "" && t != f {
			forms = append(forms, t)
		}
	}
	return forms
}

// Classify returns the sorted bucket list for a parameter name.
func Classify(name string) []string {
	set := map[string]bool{}
	for _, f := range baseForms(name) {
		for _, b := range buckets[f] {
			set[b] = true
		}
	}
	var out []string
	for b := range set {
		out = append(out, b)
	}
	sort.Strings(out)
	return out
}

// ParamHit is one classified parameter occurrence.
type ParamHit struct {
	Param   string
	URL     string
	Buckets []string
}

func (s *Scanner) Run(_ context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	seen := map[string]bool{} // param@url
	var hits []ParamHit
	byBucket := map[string]int{}
	for _, ep := range sc.Endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil || u.RawQuery == "" {
			continue
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			continue
		}
		for param := range q {
			key := strings.ToLower(param) + "@" + ep.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			bs := Classify(param)
			if len(bs) == 0 {
				continue
			}
			hits = append(hits, ParamHit{Param: param, URL: ep.URL, Buckets: bs})
			for _, b := range bs {
				byBucket[b]++
			}
		}
	}
	if len(hits) == 0 {
		return scanner.StageResult{}, nil
	}

	sort.Slice(hits, func(i, j int) bool {
		if len(hits[i].Buckets) != len(hits[j].Buckets) {
			return len(hits[i].Buckets) > len(hits[j].Buckets)
		}
		if hits[i].Param != hits[j].Param {
			return hits[i].Param < hits[j].Param
		}
		return hits[i].URL < hits[j].URL
	})

	const maxSamples = 15
	var sb strings.Builder
	n := len(hits)
	if n > maxSamples {
		n = maxSamples
	}
	var bucketNames []string
	for b := range byBucket {
		bucketNames = append(bucketNames, b)
	}
	sort.Strings(bucketNames)
	var counts []string
	for _, b := range bucketNames {
		counts = append(counts, fmt.Sprintf("%s×%d", b, byBucket[b]))
	}
	sb.WriteString("buckets: " + strings.Join(counts, ", ") + "\n")
	for _, h := range hits[:n] {
		sb.WriteString(fmt.Sprintf("- %s [%s] %s\n", h.Param, strings.Join(h.Buckets, ","), h.URL))
	}
	if len(hits) > maxSamples {
		sb.WriteString(fmt.Sprintf("…and %d more", len(hits)-maxSamples))
	}

	return scanner.StageResult{Findings: []models.Finding{{
		ID:    "params-high-value",
		Title: fmt.Sprintf("%d high-value parameter(s) worth focused injection testing", len(hits)),
		Description: "Query parameters observed on discovered endpoints were classified by attacker-interest " +
			"bucket (sqli/xss/ssrf/idor/redirect/lfi/rce/ssti). Buckets are triage hints, not vulnerabilities — " +
			"each listed URL is a candidate for manual or tool-assisted (dalfox/sqlmap) injection testing.",
		Severity:   models.SeverityInfo,
		Confidence: models.ConfidenceHigh,
		Category:   models.CategoryEndpoint,
		Target:     sc.Target.Raw,
		Evidence: models.Evidence{
			Observed: strings.TrimRight(sb.String(), "\n"),
			Location: "discovered endpoint query strings",
		},
		Source:          models.SourceCustom,
		DetectionMethod: "query-parameter classification against interest buckets",
		Remediation:     "Treat every listed parameter as untrusted input: parameterize queries, encode output, validate URLs against allowlists, and enforce object-level authorization.",
		FirstSeen:       time.Now(),
	}}}, nil
}
