// Package hiddenparams mines unlinked query parameters (Wave 1 item 20):
// for up to 2 same-host page URLs, it replays a bounded 30-name wordlist
// with a benign value and compares each response against the URL's own
// baseline plus a random-control parameter. A response that differs from
// BOTH is a candidate hidden parameter (Info intel for the Active
// stage; the interesting URLs are returned as Endpoints).
//
// Budget: 2 URLs × (1 baseline + 30 probes + 1 control) = 64 requests
// max. GET-only, benign values, no state change. Echo-guard: parameters
// already present on the URL are skipped; random-control equality kills
// the signal (reflection, not handling).
package hiddenparams

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxTargets and wordlist bound the budget: 2 × (1 + 30 + 1) = 64.
const (
	maxTargets = 2
	maxProbes  = 30
)

// paramNames is the bounded mining wordlist (benign, read-only names).
var paramNames = []string{
	"id", "page", "p", "q", "s", "search", "keyword", "query", "term",
	"category", "cat", "sort", "order", "dir", "lang", "locale", "l",
	"debug", "test", "dev", "admin", "user", "name", "title", "type",
	"action", "do", "view", "tab", "callback",
}

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "hiddenparams" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

type sig struct {
	status int
	length int // coarse bucket
	words  int
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	targets := pickTargets(sc)
	if len(targets) == 0 {
		return scanner.StageResult{}, nil
	}
	var findings []models.Finding
	var endpoints []models.Endpoint
	made := 0
	get := func(u string) *anpuhttp.Response {
		if made >= maxTargets*(1+maxProbes+1) {
			return nil
		}
		// Charge the global per-tool ledger (Wave 4 item 151); a nil
		// ledger (unit tests) means uncapped.
		if sc.Ledger != nil {
			if err := sc.Ledger.Record("hiddenparams"); err != nil {
				return nil
			}
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, u)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	for _, target := range targets {
		parsed, err := url.Parse(target)
		if err != nil {
			continue
		}
		existing := map[string]bool{}
		for k := range parsed.Query() {
			existing[strings.ToLower(k)] = true
		}
		baseResp := get(target)
		if baseResp == nil {
			continue
		}
		base := of(baseResp)
		// Random control: reflection detector.
		controlResp := get(withParam(target, "anpucontrolxyz", "anputest"))
		control := sig{}
		hasControl := false
		if controlResp != nil {
			control, hasControl = of(controlResp), true
		}
		var found []string
		for _, name := range paramNames {
			if len(found) >= 6 {
				break
			}
			if existing[strings.ToLower(name)] {
				continue // echo-guard: already linked
			}
			resp := get(withParam(target, name, "anputest"))
			if resp == nil {
				continue
			}
			got := of(resp)
			if got == base {
				continue // unhandled parameter
			}
			if hasControl && got == control {
				continue // reflection, not handling
			}
			found = append(found, name)
		}
		if len(found) > 0 {
			sort.Strings(found)
			findings = append(findings, models.Finding{
				ID:              "hiddenparams-candidates",
				Title:           fmt.Sprintf("%d candidate hidden parameter(s) on %s", len(found), displayPath(target)),
				Description:     fmt.Sprintf("Appending ?%s changes the response versus both the plain baseline and a random control parameter, so the application reads these names though nothing links them. Hand them to targeted testing. Reproduce: curl TARGET with and without ?%s=anputest and diff. GET-only, benign values.", strings.Join(found, ", "), found[0]),
				Severity:        models.SeverityInfo,
				Confidence:      models.ConfidenceMedium,
				Category:        models.CategoryExposure,
				Target:          sc.Target.Raw,
				URL:             target,
				Evidence:        models.Evidence{Observed: "params: " + strings.Join(found, ", "), Location: "param mining vs baseline + random control"},
				Source:          models.SourceEndpoints,
				DetectionMethod: "hidden-param mining, 30-name wordlist (hiddenparams, ≤64 requests)",
			})
			for _, name := range found {
				endpoints = append(endpoints, models.Endpoint{URL: withParam(target, name, "anputest"), Category: models.EndpointPage, Sources: []string{"hiddenparams"}})
			}
		}
	}
	return scanner.StageResult{Findings: findings, Endpoints: endpoints}, nil
}

// pickTargets returns up to maxTargets same-host page URLs: the scan
// target plus one discovered endpoint page.
func pickTargets(sc *scanner.ScanContext) []string {
	out := []string{sc.Target.Raw}
	for _, ep := range sc.Endpoints {
		if len(out) >= maxTargets {
			break
		}
		if ep.Category != models.EndpointPage && ep.Category != models.EndpointUnknown {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		if !strings.EqualFold(u.Hostname(), sc.Target.Host) {
			continue
		}
		dup := false
		for _, o := range out {
			if o == ep.URL {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, ep.URL)
		}
	}
	return out
}

func withParam(raw, name, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func of(resp *anpuhttp.Response) sig {
	return sig{status: resp.StatusCode, length: len(resp.Body) / 256, words: len(strings.Fields(string(resp.Body)))}
}

func displayPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	return p
}
