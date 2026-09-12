package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// sqliRule detects SQL injection indicators using error-based detection.
// It fetches a baseline first and only flags error strings that APPEAR
// after injection — pages that always render errors stay silent.
//
// Safety: low-impact — a single quote triggers a DB parse error on
// vulnerable systems but cannot modify data.
type sqliRule struct{}

func (r *sqliRule) ID() models.ActiveRuleID    { return "sqli-error-based" }
func (r *sqliRule) Name() string               { return "SQL Injection Indicator (Error-Based)" }
func (r *sqliRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *sqliRule) RequestBudget() int         { return 3 }

// sqliPayload is a minimal probe that triggers a SQL parse error on most
// databases without modifying any data.
const sqliPayload = `'`

// sqliErrorSignatures covers MySQL, PostgreSQL, SQLite, MSSQL, Oracle.
var sqliErrorSignatures = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark",
	"quoted string not properly terminated",
	"pg_query()",
	"postgresql error",
	"sqlite3.operationalerror",
	"sqlite_error",
	"ora-01756",
	"ora-00933",
	"microsoft ole db provider for sql server",
	"odbc sql server driver",
	"syntax error or access violation",
	"sqlexception",
	"invalid sql",
}

func (r *sqliRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v, Payload: sqliPayload}

	// Baseline first: an error string that is already present without
	// injection proves nothing — skip the vector instead of flagging.
	var baseline string
	switch v.Kind {
	case models.VectorJSONBody:
		jsonBody, buildErr := buildJSONBody(v.Name, v.OriginalValue)
		if buildErr != nil {
			return result, nil
		}
		resp, err := client.PostJSON(ctx, v.URL, jsonBody, nil)
		result.RequestsMade++
		if err != nil || resp == nil {
			return result, nil
		}
		baseline = strings.ToLower(string(resp.Body))
	default:
		resp, err := client.Get(ctx, v.URL)
		result.RequestsMade++
		if err != nil || resp == nil {
			return result, nil
		}
		baseline = strings.ToLower(string(resp.Body))
	}

	var (
		resp *anpuhttp.Response
		err  error
	)

	switch v.Kind {
	case models.VectorJSONBody:
		// Build proper JSON — a single quote is safe in JSON strings
		// (no escaping needed) but using buildJSONBody keeps construction
		// consistent and avoids any future edge-case surprises.
		jsonBody, buildErr := buildJSONBody(v.Name, sqliPayload)
		if buildErr != nil {
			return result, nil
		}
		resp, err = client.PostJSON(ctx, v.URL, jsonBody, nil)
		result.RequestsMade++
	default:
		injected, buildErr := buildInjectedURL(v, sqliPayload)
		if buildErr != nil {
			return result, nil
		}
		resp, err = client.Get(ctx, injected)
		result.RequestsMade++
	}

	if err != nil {
		return result, nil
	}

	body := strings.ToLower(string(resp.Body))
	for _, sig := range sqliErrorSignatures {
		// Baseline-subtracted: the signature must be NEW after
		// injection, otherwise the page always renders it.
		if strings.Contains(body, sig) && !strings.Contains(baseline, sig) {
			result.Found = true
			result.Evidence = fmt.Sprintf(
				"Database error signature %q appeared in response (status %d) after injecting single-quote into parameter %q (absent in baseline)",
				sig, resp.StatusCode, v.Name,
			)
			break
		}
	}
	return result, nil
}

func (r *sqliRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-sqli-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("SQL injection indicator in parameter %q at %s", res.Vector.Name, res.Vector.URL),
		Description:     fmt.Sprintf("Injecting a single-quote into parameter %q triggered a database error message in the response (absent before injection), indicating the parameter value is interpolated into a SQL query without sanitization.", res.Vector.Name),
		Severity:        models.SeverityHigh,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-89",
		OWASP:           "A03:2021 - Injection",
		Target:          target,
		URL:             res.Vector.URL,
		Parameter:       res.Vector.Name,
		Source:          models.SourceActive,
		DetectionMethod: "error-based SQL injection: baseline-subtracted single-quote probe triggered a recognisable database error string",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("GET %s (payload in %s=%q)", res.Vector.URL, res.Vector.Name, res.Payload)},
		Impact:          "An attacker can read, modify, or delete database contents, bypass authentication, and potentially execute OS commands depending on the database and configuration.",
		Remediation:     "Use parameterised queries or prepared statements. Never interpolate user input directly into SQL. Apply least-privilege DB accounts.",
		References:      []string{"https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
		FirstSeen:       time.Now(),
	}
}
