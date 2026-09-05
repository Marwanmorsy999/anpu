package active

// nosql.go — NoSQL Injection active rule.
//
// NoSQL injection targets databases that accept query operators as part of
// user-supplied input — most commonly MongoDB.  Unlike SQL injection which
// requires breaking out of a string literal, NoSQL injection exploits the
// fact that many frameworks merge user-supplied JSON/query-string data
// directly into the query object.
//
// # Attack vector
//
// MongoDB uses operator objects like {"$gt": ""} ("greater than empty string")
// which matches any non-empty field value.  If a login endpoint processes:
//
//	db.users.findOne({username: req.body.username, password: req.body.password})
//
// An attacker who sends:
//
//	{"username": {"$gt": ""}, "password": {"$gt": ""}}
//
// causes the query to match the first user in the collection regardless of
// the actual password — authentication bypass with no valid credentials.
//
// # Detection approach (two channels)
//
//  1. JSON body injection — POST {"field": {"$gt": ""}} to JSON-accepting
//     endpoints and compare response status/body to a baseline POST with a
//     benign value.  A status change from 401/403 → 200, or a body that
//     previously indicated failure now indicating success, is a strong signal.
//
//  2. Query-string injection — append ?field[$gt]=&field2[$gt]= to GET
//     endpoints and compare to baseline.  PHP and some Node.js frameworks
//     parse foo[$gt]=bar into {foo: {$gt: "bar"}} automatically.
//
// Both channels use a baseline → probe comparison to avoid false positives
// from endpoints that always return 200 or always return non-200.
//
// # CWE / OWASP
//
// CWE-943: Improper Neutralization of Special Elements in Data Query Logic
// OWASP A03:2021 — Injection

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

type nosqlRule struct{}

func (r *nosqlRule) ID() models.ActiveRuleID    { return "nosql-injection" }
func (r *nosqlRule) Name() string               { return "NoSQL Injection" }
func (r *nosqlRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *nosqlRule) RequestBudget() int         { return 4 }

// nosqlOperators are the MongoDB operator payloads injected per parameter.
// {"$gt": ""} is the canonical auth-bypass payload; {"$ne": null} is a
// second variant that matches any field that is not null.
var nosqlOperators = []struct {
	jsonValue string // value to inject for JSON body probes
	qsValue   string // value to inject for query-string probes (PHP bracket syntax)
	label     string
}{
	{`{"$gt":""}`, `[$gt]=`, "gt-operator"},
	{`{"$ne":null}`, `[$ne]=`, "ne-operator"},
}

// nosqlSuccessSignals are patterns in response bodies that indicate a
// previously-failed authentication or query has now succeeded.
var nosqlSuccessSignals = []string{
	"welcome",
	"dashboard",
	"logged in",
	"login successful",
	"authentication successful",
	"access granted",
	"token",
	"\"user\":",
	"\"username\":",
	"\"email\":",
	"\"role\":",
	"\"admin\"",
	"\"id\":",
}

// nosqlErrorSignals are MongoDB / Mongoose error strings that indicate the
// payload reached the database layer.
var nosqlErrorSignals = []string{
	"$where",
	"bson",
	"mongodb",
	"mongoose",
	"castError",
	"cast to string failed",
	"operator",
	"$gt",
	"$ne",
	"$regex",
	"queryfailed",
}

func (r *nosqlRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}

	switch v.Kind {
	case models.VectorJSONBody:
		return r.testJSONBody(ctx, client, v, result)
	case models.VectorQueryParam:
		return r.testQueryString(ctx, client, v, result)
	default:
		return result, nil
	}
}

// testJSONBody probes a JSON-accepting endpoint by replacing the target
// parameter value with a MongoDB operator object.
func (r *nosqlRule) testJSONBody(ctx context.Context, client *anpuhttp.Client, v models.InputVector, result models.ActiveRuleResult) (models.ActiveRuleResult, error) {
	// Baseline: POST with a benign string value.
	baselineBody := buildJSONBodyForNosql(v.Name, `"baseline-value-anpu"`)
	baseResp, err := client.PostJSON(ctx, v.URL, baselineBody, nil)
	result.RequestsMade++
	if err != nil {
		return result, nil
	}
	baseStatus := baseResp.StatusCode
	baseBodyLower := strings.ToLower(string(baseResp.Body))

	for _, op := range nosqlOperators {
		select {
		case <-ctx.Done():
			return result, nil
		default:
		}

		probeBody := buildJSONBodyForNosql(v.Name, op.jsonValue)
		result.Payload = probeBody
		probeResp, err := client.PostJSON(ctx, v.URL, probeBody, nil)
		result.RequestsMade++
		if err != nil {
			continue
		}

		found, evidence := compareNosqlResponses(baseStatus, baseBodyLower, probeResp, op.label, v.Name)
		if found {
			result.Found = true
			result.Evidence = evidence
			return result, nil
		}
	}
	return result, nil
}

// testQueryString probes a GET endpoint by appending MongoDB operator
// query parameters using PHP/Express bracket syntax.
func (r *nosqlRule) testQueryString(ctx context.Context, client *anpuhttp.Client, v models.InputVector, result models.ActiveRuleResult) (models.ActiveRuleResult, error) {
	// Baseline: GET with the original parameter value.
	baseResp, err := client.Get(ctx, v.URL)
	result.RequestsMade++
	if err != nil {
		return result, nil
	}
	baseStatus := baseResp.StatusCode
	baseBodyLower := strings.ToLower(string(baseResp.Body))

	for _, op := range nosqlOperators {
		select {
		case <-ctx.Done():
			return result, nil
		default:
		}

		// Build URL with bracket-notation operator: ?param[$gt]=
		probeURL := injectNosqlQS(v.URL, v.Name, op.qsValue)
		result.Payload = probeURL
		probeResp, err := client.Get(ctx, probeURL)
		result.RequestsMade++
		if err != nil {
			continue
		}

		found, evidence := compareNosqlResponses(baseStatus, baseBodyLower, probeResp, op.label, v.Name)
		if found {
			result.Found = true
			result.Evidence = evidence
			return result, nil
		}
	}
	return result, nil
}

// compareNosqlResponses checks for the two key signals:
// 1. Auth bypass: status changes from 4xx → 2xx (or baseline was failure, probe is success)
// 2. DB error disclosure: nosqlErrorSignals appear in response body
func compareNosqlResponses(baseStatus int, baseBodyLower string, probe *anpuhttp.Response, opLabel, paramName string) (bool, string) {
	probeStatus := probe.StatusCode
	probeBodyLower := strings.ToLower(string(probe.Body))

	// Signal 1: status upgrade from 4xx → 2xx (auth bypass).
	if baseStatus >= 400 && probeStatus >= 200 && probeStatus < 300 {
		return true, fmt.Sprintf(
			"NoSQL injection (%s) caused status change %d → %d on parameter %q. "+
				"MongoDB operator in request body changed authentication outcome — possible auth bypass.",
			opLabel, baseStatus, probeStatus, paramName,
		)
	}

	// Signal 2: success keywords appear in probe but not baseline.
	for _, sig := range nosqlSuccessSignals {
		if strings.Contains(probeBodyLower, sig) && !strings.Contains(baseBodyLower, sig) {
			return true, fmt.Sprintf(
				"NoSQL injection (%s) on parameter %q caused success indicator %q to appear in response "+
					"(absent in baseline). Possible authentication bypass via MongoDB operator injection.",
				opLabel, paramName, sig,
			)
		}
	}

	// Signal 3: DB error strings indicating the operator reached the query engine.
	for _, sig := range nosqlErrorSignals {
		if strings.Contains(probeBodyLower, sig) && !strings.Contains(baseBodyLower, sig) {
			return true, fmt.Sprintf(
				"NoSQL error string %q appeared in response after injecting %s operator into parameter %q. "+
					"The MongoDB operator reached the query engine before being rejected.",
				sig, opLabel, paramName,
			)
		}
	}

	return false, ""
}

// buildJSONBodyForNosql builds a one-field JSON object with a raw (pre-encoded) value.
// value must already be valid JSON (e.g. `{"$gt":""}` or `"baseline-value"`).
func buildJSONBodyForNosql(field, value string) string {
	// Validate field name is safe to interpolate.
	fieldJSON, _ := json.Marshal(field)
	return fmt.Sprintf("{%s:%s}", string(fieldJSON), value)
}

// injectNosqlQS builds a URL with a bracket-notation operator parameter appended.
// e.g. https://example.com/login?username[$gt]=
func injectNosqlQS(rawURL, paramName, opSuffix string) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	// opSuffix is like "[$gt]=" — append it directly after param name.
	return rawURL + sep + paramName + opSuffix
}

func (r *nosqlRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	confidence := models.ConfidenceMedium
	if strings.Contains(res.Evidence, "status change") || strings.Contains(res.Evidence, "auth bypass") {
		confidence = models.ConfidenceHigh
	}

	return models.Finding{
		ID:    fmt.Sprintf("active-nosql-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("NoSQL Injection at %s (parameter: %s)", res.Vector.URL, res.Vector.Name),
		Description: fmt.Sprintf(
			"The endpoint at %s appears vulnerable to NoSQL injection. "+
				"MongoDB operator objects (e.g. {\"$gt\":\"\"}) injected into parameter %q "+
				"produced a response that differs from the baseline in a way consistent with "+
				"authentication bypass or database error disclosure. Detection: %s",
			res.Vector.URL, res.Vector.Name, res.Evidence,
		),
		Severity:        models.SeverityHigh,
		Confidence:      confidence,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-943",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "MongoDB operator injection ($gt, $ne) via JSON body and query-string bracket notation; baseline vs. probe comparison",
		Evidence: models.Evidence{
			Observed:       res.Evidence,
			Location:       res.Vector.URL,
			RequestSummary: fmt.Sprintf("POST/GET %s with MongoDB operator payload", res.Vector.URL),
		},
		Impact: "An attacker can bypass authentication by injecting {\"$gt\":\"\"} into username and password fields, " +
			"gaining access to any account (typically the first user in the collection, often an admin). " +
			"May also allow data exfiltration via operator-based query manipulation.",
		Remediation: "Never merge user-supplied data directly into query objects. " +
			"Use parameterised queries / schema validation (e.g. Mongoose schema with strict types). " +
			"Validate that input values are the expected primitive type (string/number) before passing to the database. " +
			"Enable MongoDB's strict mode and disable the $where operator in production.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
			"https://cwe.mitre.org/data/definitions/943.html",
			"https://www.mongodb.com/docs/manual/core/security-injection-attacks/",
		},
		FirstSeen: time.Now(),
	}
}
