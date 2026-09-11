// Package soap discovers SOAP/WSDL exposure (Wave 2 item 1): bounded
// GETs against well-known WSDL/service paths, matched for WSDL and
// SOAP-envelope markers with control-difference required. Disclosed
// operation names are harvested as API endpoints for AuthZ/Active.
// GET-only, read-only, no SOAPAction invocation, no envelope POSTs.
package soap

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/fpmatch"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: 1 control + 1 lazy root + 8 probes.
const maxRequests = 10

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "soap" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

var wsdlPaths = []string{
	"/soap", "/Soap", "/wsdl", "/service.wsdl", "/services.wsdl",
	"/api.wsdl", "/soap.wsdl", "/axis2/services",
}

var (
	wsdlMarkerRe = regexp.MustCompile(`(?i)<\s*(wsdl:)?definitions[\s>]`)
	envelopeRe   = regexp.MustCompile(`(?i)<\s*(soap:)?Envelope[\s>]`)
	opRe         = regexp.MustCompile(`(?i)<\s*(wsdl:)?operation\s+name\s*=\s*"([^"]+)"`)
)

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	get := func(path string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, strings.TrimSuffix(sc.Target.Raw, "/")+path)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	controlWords := map[string]struct{}{}
	if control := get("/anpu-soap-control-404"); control != nil {
		controlWords = wordSet(control.Body)
	}

	// Lazy app-shell root (Phase 2): fetched only on the first marker
	// match so the common no-finding path costs nothing extra.
	var rootWords map[string]struct{}
	rootFetched := false
	ensureRoot := func() {
		if rootFetched {
			return
		}
		rootFetched = true
		if root := get("/"); root != nil && len(root.Body) > 0 {
			rootWords = wordSet(root.Body)
		}
	}

	var findings []models.Finding
	var endpoints []models.Endpoint
	for _, p := range wsdlPaths {
		if made >= maxRequests {
			break
		}
		resp := get(p)
		if resp == nil || resp.StatusCode != 200 || len(resp.Body) < 64 {
			continue
		}
		body := string(resp.Body)
		isWSDL := wsdlMarkerRe.MatchString(body)
		isEnv := envelopeRe.MatchString(body)
		if !isWSDL && !isEnv {
			continue
		}
		if overlap(wordSet(resp.Body), controlWords) > 0.85 {
			continue // baseline-subtract: same page as control
		}
		if fpmatch.IsWAFBlockPage(resp.Body) {
			continue // WAF block page served as 200, not a WSDL document
		}
		ensureRoot()
		if len(rootWords) > 0 && overlap(wordSet(resp.Body), rootWords) > 0.85 {
			continue // app-shell: same page as site root
		}
		u := strings.TrimSuffix(sc.Target.Raw, "/") + p
		kind := "SOAP envelope"
		if isWSDL {
			kind = "WSDL document"
		}
		ops := opNames(body)
		desc := fmt.Sprintf("The path %s serves a %s: the full service contract is public. Disable public WSDL in production or gate it by auth, and test every disclosed operation for authz. Reproduce: curl -s TARGET%s.", p, kind, p)
		if len(ops) > 0 {
			shown := ops
			if len(shown) > 10 {
				shown = shown[:10]
			}
			desc += fmt.Sprintf(" Disclosed operations include: %s.", strings.Join(shown, ", "))
		}
		findings = append(findings, models.Finding{
			ID: "soap-" + slug(p), Title: "SOAP/WSDL exposed: " + p,
			Description: desc, Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh,
			Category: models.CategoryExposure, Target: sc.Target.Raw, URL: u,
			Evidence: models.Evidence{Observed: fmt.Sprintf("200 + %s marker (%d bytes)", kind, len(resp.Body)), Location: p},
			Source:   models.SourceRecon, DetectionMethod: "WSDL/SOAP marker probe with 404 baseline (soap, ≤9 requests)",
			Remediation: "Remove public WSDL; authorize every operation.",
		})
		endpoints = append(endpoints, models.Endpoint{URL: u, Category: models.EndpointAPI, Sources: []string{"soap"}})
		if len(findings) >= 3 {
			break
		}
	}
	return scanner.StageResult{Findings: findings, Endpoints: endpoints}, nil
}

// opNames extracts wsdl:operation names (pure, deterministic).
func opNames(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range opRe.FindAllStringSubmatch(body, -1) {
		if seen[m[2]] {
			continue
		}
		seen[m[2]] = true
		out = append(out, m[2])
	}
	sort.Strings(out)
	return out
}

func slug(path string) string {
	s := strings.ToLower(strings.Trim(path, "/"))
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, "/", "-")
	if s == "" {
		s = "root"
	}
	return s
}

func wordSet(b []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for _, w := range strings.Fields(strings.ToLower(string(b))) {
		if len(w) > 2 {
			out[w] = struct{}{}
		}
	}
	return out
}

func overlap(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	n := 0
	for w := range a {
		if _, ok := b[w]; ok {
			n++
		}
	}
	return float64(n) / float64(len(a))
}
