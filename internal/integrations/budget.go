// Package integrations — budget.go: cumulative external-tool time
// budget (Phase 4). Ultra stages dozens of wrappers; without a cap the
// worst case is a surprise time sink. ANPU_TOOL_BUDGET_SEC (seconds,
// 0/unset = uncapped default, behavior unchanged) bounds cumulative
// external-binary wall time across GenericScanner runs in one process.
// When exhausted, remaining tools skip with an explicit reason naming
// the spent/limit figures and the opt-out — honest skip, never silent.
package integrations

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// toolBudgetSpent tracks consumed external-tool seconds (atomic).
var toolBudgetSpent int64

// ToolBudgetLimit reads the configured cap (0 = uncapped).
func ToolBudgetLimit() int64 {
	raw := strings.TrimSpace(os.Getenv("ANPU_TOOL_BUDGET_SEC"))
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// ToolBudgetSpent returns consumed external-tool seconds.
func ToolBudgetSpent() int64 { return atomic.LoadInt64(&toolBudgetSpent) }

// ToolBudgetAdd records one finished invocation (ceiling seconds).
func ToolBudgetAdd(dur time.Duration) {
	secs := int64(dur / time.Second)
	if dur%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	atomic.AddInt64(&toolBudgetSpent, secs)
}

// ToolBudgetReset clears the spent counter (tests; process start is 0).
func ToolBudgetReset() { atomic.StoreInt64(&toolBudgetSpent, 0) }

// ToolBudgetAllow reports whether a tool with worst-case timeoutSecs may
// start under the cap. Uncapped budgets always allow.
func ToolBudgetAllow(timeoutSecs int) (bool, string) {
	limit := ToolBudgetLimit()
	if limit <= 0 {
		return true, ""
	}
	spent := ToolBudgetSpent()
	if spent+int64(timeoutSecs) > limit {
		return false, fmt.Sprintf("tool budget exhausted (spent %ds of %ds cap; next tool needs up to %ds) — raise ANPU_TOOL_BUDGET_SEC or set 0 for uncapped",
			spent, limit, timeoutSecs)
	}
	return true, ""
}
