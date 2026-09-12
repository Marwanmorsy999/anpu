package active

import "github.com/Marwanmorsy999/anpu/pkg/models"

// AdversarialEnabled controls whether the 6 hazardous adversarial rules
// (jwt, massassign, business, race, smuggling, protopollute) are allowed
// to run. They are opt-in via --adversarial --confirm-authorized (authorized
// ultra/adversarial only). Default false keeps safe/advanced scans non-hazardous.
var AdversarialEnabled bool

// AdversarialConfirmed must be true together with AdversarialEnabled to
// actually run the hazardous probes. This two-flag gate prevents accidental
// use without explicit authorization confirmation.
var AdversarialConfirmed bool

// IsAdversarialEnabled reports whether adversarial probes may run.
func IsAdversarialEnabled() bool { return AdversarialEnabled && AdversarialConfirmed }

func isAdversarialRule(id models.ActiveRuleID) bool {
	switch id {
	case "jwt-weak-verification", "mass-assignment", "business-logic-tamper", "race-condition", "http-smuggling", "prototype-pollution",
		"session-fixation", "exposed-session-id", "logout-invalidation", "password-policy-weak":
		return true
	default:
		return false
	}
}
