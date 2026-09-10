// Package http — budget.go: global per-tool request budget ledger.
//
// Every active probe already declares a per-vector RequestBudget; the
// ledger adds the orthogonal global cap: no single tool/stage may exceed
// its allotment in one scan, and the scan as a whole stays under
// maxTotal. This is what `anpu wordlists`/fuzz stages consult before
// expanding a payload pack.
//
// Thread-safe; Record is the only mutating path. Going over budget
// returns an error — callers warn-and-skip, never fatal (house style).
package http

import (
	"fmt"
	"sync"
)

// Default caps: polite natives stay small, fuzzers get room but stay
// bounded. Ultra fuzz stages must still consult the ledger per batch.
const (
	DefaultMaxTotal      = 2000
	DefaultCapNativeSafe = 12
	DefaultCapAdvanced   = 60
	DefaultCapUltra      = 500
)

// Ledger tracks per-tool request counts against per-tool and global caps.
type Ledger struct {
	mu       sync.Mutex
	counts   map[string]int
	caps     map[string]int
	maxTotal int
	total    int
}

// NewLedger builds a ledger with a global cap (0 = DefaultMaxTotal).
func NewLedger(maxTotal int) *Ledger {
	if maxTotal <= 0 {
		maxTotal = DefaultMaxTotal
	}
	return &Ledger{counts: map[string]int{}, caps: map[string]int{}, maxTotal: maxTotal}
}

// SetCap overrides the per-tool cap (0 = unlimited for that tool).
func (l *Ledger) SetCap(tool string, cap int) {
	l.mu.Lock()
	l.caps[tool] = cap
	l.mu.Unlock()
}

// CapFor returns the effective cap for a tool (0 = unlimited).
func (l *Ledger) CapFor(tool string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.caps[tool]
}

// Record charges one request to tool. It returns an error when the
// tool cap or the global cap would be exceeded (caller should stop and
// report what completed so far).
func (l *Ledger) Record(tool string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cap := l.caps[tool]; cap > 0 && l.counts[tool] >= cap {
		return fmt.Errorf("budget exhausted for %s (%d requests)", tool, cap)
	}
	if l.total >= l.maxTotal {
		return fmt.Errorf("global request budget exhausted (%d requests)", l.maxTotal)
	}
	l.counts[tool]++
	l.total++
	return nil
}

// Count returns requests charged to tool so far.
func (l *Ledger) Count(tool string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[tool]
}

// Total returns all requests charged so far.
func (l *Ledger) Total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// Remaining returns remaining requests for tool (global remaining when
// the tool has no cap; -1 means unlimited on both axes).
func (l *Ledger) Remaining(tool string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	remGlobal := l.maxTotal - l.total
	if cap, ok := l.caps[tool]; ok && cap > 0 {
		remTool := cap - l.counts[tool]
		if remTool < remGlobal {
			return remTool
		}
	}
	if remGlobal < 0 {
		return 0
	}
	return remGlobal
}
