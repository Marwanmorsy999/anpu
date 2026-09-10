package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// graphql_abuse.go — safe GraphQL abuse checks (graphql-cop parity).
//
// Beyond introspection disclosure, GraphQL endpoints commonly allow:
// batching (brute-force amplification past request-count rate limits),
// field suggestions (schema reconstruction aid), queries over GET
// (CSRF-able operations), and unbounded query depth (DoS). All probes
// below are read-only __typename-level queries — no mutations, no deep
// fan-out, no state changes.

// postGraphQLBody sends one raw GraphQL-over-HTTP request via anpuhttp
// (redirect guards, proxy, limiter, local-net policy).
func postGraphQLBody(ctx context.Context, endpoint, contentType, body string, authHeaders map[string]string, client *anpuhttp.Client, timeout time.Duration) (int, []byte, error) {
	if client == nil {
		client = anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// anpuhttp PostJSON sets JSON content-type; for other content types
	// merge via extra headers (authHeaders win for auth).
	hdrs := map[string]string{}
	for k, v := range authHeaders {
		hdrs[k] = v
	}
	// contentType is always application/json in current probes.
	resp, err := client.PostJSON(tctx, endpoint, body, hdrs)
	if err != nil || resp == nil {
		return 0, nil, err
	}
	data := resp.Body
	if len(data) > 1<<20 {
		data = data[:1<<20]
	}
	_ = contentType
	return resp.StatusCode, data, nil
}

// CheckGraphQLBatching tests array-based query batching: two trivial
// queries in one HTTP request. Success means brute-force/OTP attacks
// can hide N attempts inside a single request past rate limiters.
func CheckGraphQLBatching(ctx context.Context, endpoint string, authHeaders map[string]string, client *anpuhttp.Client, timeout time.Duration) *models.Finding {
	status, data, err := postGraphQLBody(ctx, endpoint, "application/json",
		`[{"query":"{__typename}"},{"query":"{__typename}"}]`, authHeaders, client, timeout)
	if err != nil || status != 200 || len(data) == 0 {
		return nil
	}
	var batch []struct {
		Data   map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &batch); err != nil || len(batch) < 2 {
		return nil
	}
	for _, item := range batch {
		if len(item.Errors) > 0 {
			for _, e := range item.Errors {
				if strings.Contains(strings.ToLower(e.Message), "batch") {
					return nil // explicitly rejected — protected
				}
			}
			return nil // other errors — inconclusive, stay silent
		}
		if _, ok := item.Data["__typename"]; !ok {
			return nil
		}
	}
	f := models.Finding{
		ID:    fmt.Sprintf("graphql-batching-%d", time.Now().UnixNano()),
		Title: "GraphQL query batching enabled (brute-force amplification)",
		Description: fmt.Sprintf(
			"The GraphQL endpoint at %s executed two batched queries inside a single HTTP request. "+
				"Batching lets attackers pack hundreds of login/OTP attempts into one request, sailing past rate limiters that count HTTP requests instead of operations.",
			endpoint,
		),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryConfiguration,
		CWE:             "CWE-770",
		OWASP:           "A04:2021 - Insecure Design",
		Target:          endpoint,
		URL:             endpoint,
		Source:          models.SourceAPI,
		DetectionMethod: "GraphQL abuse check: array-batched __typename queries both executed",
		Evidence: models.Evidence{
			Observed:       "HTTP 200 with 2 executed results for 1 batched request",
			Location:       endpoint,
			RequestSummary: "POST " + endpoint + " ([{query},{query}] batch)",
		},
		Impact:      "Credential stuffing, OTP brute-forcing, and resource enumeration at 100x the rate limiter's allowance with minimal log footprint.",
		Remediation: "Disable query batching, or cap batched operations per request and rate-limit at the operation level rather than per HTTP request.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
		},
		FirstSeen: time.Now(),
	}
	return &f
}

// CheckGraphQLFieldSuggestions tests whether invalid fields leak
// "Did you mean …?" hints that rebuild disabled introspection.
func CheckGraphQLFieldSuggestions(ctx context.Context, endpoint string, authHeaders map[string]string, client *anpuhttp.Client, timeout time.Duration) *models.Finding {
	status, data, err := postGraphQLBody(ctx, endpoint, "application/json",
		`{"query":"{__typename nonexistentfieldanpu123}"}`, authHeaders, client, timeout)
	if err != nil || status != 200 || len(data) == 0 {
		return nil
	}
	var doc struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Errors) == 0 {
		return nil
	}
	var hint string
	for _, e := range doc.Errors {
		if strings.Contains(strings.ToLower(e.Message), "did you mean") {
			hint = e.Message
			break
		}
	}
	if hint == "" {
		return nil
	}
	if len(hint) > 200 {
		hint = hint[:200] + "…"
	}
	f := models.Finding{
		ID:    fmt.Sprintf("graphql-suggestions-%d", time.Now().UnixNano()),
		Title: "GraphQL field suggestions enabled (schema reconstruction aid)",
		Description: fmt.Sprintf(
			"The GraphQL endpoint at %s answers invalid fields with suggestions. Attackers use these hints to reconstruct a hidden schema field-by-field (Clairvoyance-style), defeating disabled introspection.",
			endpoint,
		),
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryConfiguration,
		CWE:             "CWE-200",
		Target:          endpoint,
		URL:             endpoint,
		Source:          models.SourceAPI,
		DetectionMethod: "GraphQL abuse check: invalid field elicited a 'Did you mean' suggestion",
		Evidence: models.Evidence{
			Observed:       hint,
			Location:       endpoint,
			RequestSummary: "POST " + endpoint + " (invalid field query)",
		},
		Impact:      "Accelerated schema recovery on endpoints that disabled introspection.",
		Remediation: "Disable field suggestions / 'did you mean' hints in production error responses.",
		FirstSeen:   time.Now(),
	}
	return &f
}

// CheckGraphQLGetQueries tests whether queries execute over HTTP GET.
// Pure-GET query support is Info (mutations-over-GET untested — a Medium
// requires proof a mutation actually executes over GET, a future probe).
func CheckGraphQLGetQueries(ctx context.Context, endpoint string, authHeaders map[string]string, client *anpuhttp.Client, timeout time.Duration) *models.Finding {
	u := endpoint
	if strings.Contains(u, "?") {
		u += "&"
	} else {
		u += "?"
	}
	u += "query=" + url.QueryEscape("{__typename}")
	if client == nil {
		client = anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := client.DoWithHeaders(tctx, "GET", u, authHeaders)
	if err != nil || resp == nil {
		return nil
	}
	if resp.StatusCode != 200 {
		return nil
	}
	data := resp.Body
	if len(data) == 0 {
		return nil
	}
	if len(data) > 1<<20 {
		data = data[:1<<20]
	}
	var doc struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	if _, ok := doc.Data["__typename"]; !ok {
		return nil
	}
	f := models.Finding{
		ID:    fmt.Sprintf("graphql-get-%d", time.Now().UnixNano()),
		Title: "GraphQL queries accepted over HTTP GET (CSRF exposure)",
		Description: fmt.Sprintf(
			"The GraphQL endpoint at %s executes queries sent as GET requests. State-changing mutations reachable over GET can be triggered cross-origin (plain links, image tags) with no preflight, enabling CSRF against API operations. Mutations-over-GET untested in this probe.",
			endpoint,
		),
		Severity:        models.SeverityInfo,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryConfiguration,
		CWE:             "CWE-352",
		Target:          endpoint,
		URL:             endpoint,
		Source:          models.SourceAPI,
		DetectionMethod: "GraphQL abuse check: __typename query executed via GET",
		Evidence: models.Evidence{
			Observed:       "HTTP 200 with data for GET ?query={__typename}",
			Location:       endpoint,
			RequestSummary: "GET " + endpoint + "?query={__typename}",
		},
		Impact:      "Cross-site request forgery against GraphQL mutations without token or preflight protection.",
		Remediation: "Accept queries over POST only (or require CSRF tokens / custom headers for GET), and never allow mutations over GET.",
		FirstSeen:   time.Now(),
	}
	return &f
}

// graphqlDepthProbe is a deeply-nested but cheap introspection query
// (~12 levels of __schema traversal, no fan-out).
const graphqlDepthProbe = `{"query":"{__schema{queryType{fields{args{type{ofType{fields{args{type{ofType{name}}}}}}}}}}}"}`

// CheckGraphQLDepthLimit tests whether deeply-nested queries are
// rejected. Call only when introspection succeeded (so the probe is
// schema-valid); a 200 without depth errors means no limit.
func CheckGraphQLDepthLimit(ctx context.Context, endpoint string, authHeaders map[string]string, client *anpuhttp.Client, timeout time.Duration) *models.Finding {
	status, data, err := postGraphQLBody(ctx, endpoint, "application/json", graphqlDepthProbe, authHeaders, client, timeout)
	if err != nil || status != 200 || len(data) == 0 {
		return nil
	}
	lower := strings.ToLower(string(data))
	for _, marker := range []string{"max depth", "maxdepth", "too deep", "depth limit", "complexity", "too complex", "query too large"} {
		if strings.Contains(lower, marker) {
			return nil // a limit fired — protected
		}
	}
	var doc struct {
		Data   map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Data) == 0 {
		return nil
	}
	f := models.Finding{
		ID:    fmt.Sprintf("graphql-depth-%d", time.Now().UnixNano()),
		Title: "GraphQL query depth not limited (DoS exposure)",
		Description: fmt.Sprintf(
			"The GraphQL endpoint at %s executed a deeply-nested introspection query with no depth/complexity rejection. "+
				"Attackers nest expensive fields and aliases until resolution exhausts server resources — a single small request can cause disproportionate load.",
			endpoint,
		),
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryConfiguration,
		CWE:             "CWE-770",
		Target:          endpoint,
		URL:             endpoint,
		Source:          models.SourceAPI,
		DetectionMethod: "GraphQL abuse check: deep __schema nesting executed without depth error",
		Evidence: models.Evidence{
			Observed:       "HTTP 200 with data for 12-level nested query, no depth/complexity error",
			Location:       endpoint,
			RequestSummary: "POST " + endpoint + " (nested introspection query)",
		},
		Impact:      "Denial of service via cheap nested/aliased queries consuming disproportionate resolver resources.",
		Remediation: "Enforce max query depth (e.g. 7–10) and query-complexity scoring; reject or charge over-budget queries before execution.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
		},
		FirstSeen: time.Now(),
	}
	return &f
}

// CheckGraphQLAliasFlood tests whether 100 aliased __typename fields are executed
// without complexity rejection (DoS via alias flood). Budget 1 probe via anpuhttp
// (read-only, 100 aliases × __typename, no fan-out); API abuse budget 10s×3 max
// enforced by caller (scanner.go) so this probe counts toward the 3–4 budget.
func CheckGraphQLAliasFlood(ctx context.Context, endpoint string, authHeaders map[string]string, client *anpuhttp.Client, timeout time.Duration) *models.Finding {
	var sb strings.Builder
	sb.WriteString(`{"query":"{`)
	for i := 0; i < 100; i++ {
		sb.WriteString("a" + strconv.Itoa(i) + ": __typename ")
	}
	sb.WriteString(`}"}`)
	query := sb.String()
	status, data, err := postGraphQLBody(ctx, endpoint, "application/json", query, authHeaders, client, timeout)
	if err != nil || status != 200 || len(data) == 0 {
		return nil
	}
	lower := strings.ToLower(string(data))
	for _, marker := range []string{"max aliases", "too many aliases", "alias limit", "complexity", "too complex", "query too large", "max depth"} {
		if strings.Contains(lower, marker) {
			return nil // protected
		}
	}
	var doc struct {
		Data   map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Data) < 100 {
		// If fewer than 100 aliases returned, still check if at least 50 executed — indicates no limit.
		if len(doc.Data) < 50 {
			return nil
		}
	}
	// If we get here, server executed ~100 aliases without complaint.
	f := models.Finding{
		ID:    fmt.Sprintf("graphql-alias-%d", time.Now().UnixNano()),
		Title: "GraphQL alias flood not limited (DoS via 100 aliases)",
		Description: fmt.Sprintf(
			"The GraphQL endpoint at %s executed 100 aliased __typename fields in one request with no complexity rejection. "+
				"Attackers can pack hundreds of field resolutions into a single request, amplifying DoS and bypassing depth limits.",
			endpoint,
		),
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryConfiguration,
		CWE:             "CWE-770",
		Target:          endpoint,
		URL:             endpoint,
		Source:          models.SourceAPI,
		DetectionMethod: "GraphQL abuse check: 100-alias __typename flood executed without alias/complexity error (via anpuhttp)",
		Evidence: models.Evidence{
			Observed:       fmt.Sprintf("HTTP 200 with %d alias results for 100-alias flood", len(doc.Data)),
			Location:       endpoint,
			RequestSummary: "POST " + endpoint + " (100-alias flood)",
		},
		Impact:      "Denial of service via alias amplification — one small request triggers 100× resolver work.",
		Remediation: "Enforce max alias count (e.g., 10–15) and query complexity scoring; reject over-budget queries before execution.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
		},
		FirstSeen: time.Now(),
	}
	return &f
}
