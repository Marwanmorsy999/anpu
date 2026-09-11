package active

// ultra.go — ultra-only second-family confirmations (Phase 3).
//
// safe runs no active engines; advanced runs every ungated rule with
// the Phase 1 corroboration contract. ultra runs the same rules PLUS
// a small number of exclusive confirmation paths that spend extra
// requests to turn single-technique differentials into corroborated
// findings:
//
//   - XSS: a second benign tag family (<u> vs <b>) must also reflect
//     unescaped → confidence Medium → High.
//   - Command injection: a second metacharacter family must raise the
//     same error-signal class → confidence Low → Medium, review cleared.
//   - Blind timing: a short-sleep payload must scale against the long
//     sleep (delay-scaling) → Medium/Medium → High/High.
//
// Wiring mirrors the adversarial gate: runScan sets the package flag
// after profile normalization, so level shortcuts inherit it. Rules
// check UltraConfirmEnabled() and stay within their declared
// RequestBudget. Smuggling deliberately has no ultra upgrade — length
// differentials cannot confirm a desync at any budget.

// ultraConfirm gates ultra-only confirmation probes. Default false:
// advanced behavior is byte-identical whether or not ultra exists.
var ultraConfirm bool

// SetUltraConfirm enables or disables ultra confirmations. Called once
// from runScan after profile normalization.
func SetUltraConfirm(b bool) { ultraConfirm = b }

// UltraConfirmEnabled reports whether ultra confirmation probes may run.
func UltraConfirmEnabled() bool { return ultraConfirm }
