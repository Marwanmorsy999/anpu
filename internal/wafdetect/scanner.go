// Package wafdetect fingerprints web-application-firewall behavior
// (Wave 2 item 3): a benign baseline, a random control, and two canary
// probes (XSS-shaped query value, traversal-shaped path suffix). A
// canary that flips to a block status (403/406/419/429/501) or carries
// vendor block markers — while baseline and control stay 200 —
// identifies filtering; header/body vendor signatures name the WAF.
// GET-only, ≤5 requests, inert canary strings, no payload detonation.
package wafdetect

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic: baseline + control + 2 canaries.
const maxRequests = 5

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "wafdetect" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

// vendorFingerprints maps vendor → header/body markers (lowercase).
// Pure data, matched case-insensitively by identifyVendor.
func vendorFingerprints() map[string][]string {
	return map[string][]string{
		"Cloudflare":        {"cf-ray", "cloudflare", "__cf_bm", "attention required"},
		"AWS WAF":           {"awselb", "x-amzn-waf", "aws-waf"},
		"Akamai":            {"akamai", "akamaighost", "reference #"},
		"Imperva/Incapsula": {"incapsula", "incap_ses", "_incap_", "x-iinfo"},
		"Sucuri":            {"x-sucuri-id", "sucuri", "access denied - sucuri"},
		"Fastly":            {"fastly", "x-fastly-request-id"},
		"F5 BIG-IP ASM":     {"f5", "bigip", "the requested url was rejected", "x-waf-event"},
		"Fortinet FortiWeb": {"fortiwaf", "fortigate", "fortinet"},
		"Barracuda":         {"barra", "x-barracuda"},
		"Cloud Armor (GCP)": {"google", "x-cloud-trace-context"},
		"Azure WAF":         {"azure", "x-azure-ref"},
		"ModSecurity":       {"mod_security", "modsecurity", "not acceptable"},
	}
}

// identifyVendor matches WAF markers in headers+body (pure, tested via behavior).
func identifyVendor(headers map[string]string, body string) string {
	lb := strings.ToLower(body)
	for vendor, markers := range vendorFingerprints() {
		for _, m := range markers {
			for _, hv := range headers {
				if strings.Contains(strings.ToLower(hv), m) {
					return vendor
				}
			}
			if strings.Contains(lb, m) {
				return vendor
			}
		}
	}
	return ""
}

// blockStatus reports whether a status looks like a filter block.
func blockStatus(code int) bool {
	switch code {
	case 403, 406, 409, 419, 429, 501, 506, 509:
		return true
	}
	return false
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	get := func(u string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
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

	base := get(sc.Target.Raw)
	if base == nil || base.StatusCode != 200 {
		return scanner.StageResult{}, nil
	}
	control := get(withParam(sc.Target.Raw, "anpucontrolxyz", "anputest9"))
	withSuffix := get(strings.TrimSuffix(sc.Target.Raw, "/") + "/anpucanary<script>alert(1)</script>")
	queryCanary := get(withParam(sc.Target.Raw, "anpuq", "<script>alert(1)</script>"))

	blocked := map[string]*anpuhttp.Response{}
	if withSuffix != nil && blockStatus(withSuffix.StatusCode) {
		blocked["path canary"] = withSuffix
	}
	if queryCanary != nil && blockStatus(queryCanary.StatusCode) {
		blocked["query canary"] = queryCanary
	}
	// Control must stay clean: if the control is also blocked, the host
	// blocks everything (parking/catch-all), not our canaries.
	if control != nil && blockStatus(control.StatusCode) {
		return scanner.StageResult{}, nil
	}
	if len(blocked) == 0 {
		return scanner.StageResult{}, nil
	}
	// Name the vendor from the first blocked response.
	var vendor, evidence string
	for kind, resp := range blocked {
		hdrs := map[string]string{}
		for k := range resp.Header {
			hdrs[k] = resp.Header.Get(k)
		}
		if v := identifyVendor(hdrs, string(resp.Body)); v != "" {
			vendor = v
		}
		evidence = fmt.Sprintf("%s → %d", kind, resp.StatusCode)
		break
	}
	title := "Filtering observed, vendor unknown (test filter semantics before tuning payloads)"
	severity := models.SeverityInfo
	if vendor != "" {
		title = "WAF detected: " + vendor
		severity = models.SeverityLow
	}
	return scanner.StageResult{Findings: []models.Finding{{
		ID: "wafdetect-filtering", Title: title,
		Description: fmt.Sprintf("Benign canaries (%s) flip to block statuses while baseline and random control stay 200: a filter/WAF sits in front and normalizes hostile input. Tune follow-up probes to its semantics (it already sees the easy payloads). Canary strings only — nothing detonated. Reproduce: curl TARGET with ?anpuq=<script>alert(1)</script> and compare to baseline.", evidence),
		Severity:    severity, Confidence: models.ConfidenceMedium, Category: models.CategoryExposure,
		Target: sc.Target.Raw, URL: sc.Target.Raw,
		Evidence: models.Evidence{Observed: evidence, Location: "canary vs baseline+control"},
		Source:   models.SourceRecon, DetectionMethod: "canary block-behavior matrix (wafdetect, ≤5 requests)",
	}}}, nil
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
