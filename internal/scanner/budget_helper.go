// Package scanner — budget helper.
package scanner

import (
	"fmt"
)

// ChargeBudget charges one request against the stage's shared ledger. It
// returns nil when the request is allowed (or when no ledger is present,
// which means uncapped — tests, custom pipelines). On exhaustion it
// returns the ledger's error so the caller can warn-and-skip.
//
// Scanners call this at the same point they previously incremented their
// local `made` counter: once per client-method call, before issuing the
// request.
func ChargeBudget(sc *ScanContext) error {
	if sc == nil || sc.Ledger == nil {
		return nil
	}
	return sc.Ledger.Record(sc.StageLabel)
}

// BudgetExhaustedWarning returns the warning string a stage appends when
// its budget is exhausted.
func BudgetExhaustedWarning(sc *ScanContext) string {
	label := ""
	if sc != nil {
		label = sc.StageLabel
	}
	if label == "" {
		label = "stage"
	}
	return fmt.Sprintf("budget exhausted for %s", label)
}
