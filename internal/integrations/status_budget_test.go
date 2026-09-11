package integrations

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Phase 4: the cumulative tool budget defaults to uncapped (no behavior
// change) and enforces honestly when ANPU_TOOL_BUDGET_SEC is set.
func TestToolBudgetUncappedByDefault(t *testing.T) {
	t.Setenv("ANPU_TOOL_BUDGET_SEC", "")
	ToolBudgetReset()
	if ok, _ := ToolBudgetAllow(3600); !ok {
		t.Fatal("uncapped budget must allow anything")
	}
}

func TestToolBudgetEnforces(t *testing.T) {
	t.Setenv("ANPU_TOOL_BUDGET_SEC", "10")
	ToolBudgetReset()
	if ok, _ := ToolBudgetAllow(5); !ok {
		t.Fatal("5s must fit in 10s budget")
	}
	ToolBudgetAdd(8 * time.Second)
	if ok, msg := ToolBudgetAllow(5); ok {
		t.Fatal("8 spent + 5 needed must exceed 10 cap")
	} else if !strings.Contains(msg, "tool budget exhausted") || !strings.Contains(msg, "ANPU_TOOL_BUDGET_SEC") {
		t.Fatalf("skip reason must name budget + knob, got %q", msg)
	}
	if ok, _ := ToolBudgetAllow(2); !ok {
		t.Fatal("8 spent + 2 needed must still fit 10 cap")
	}
	ToolBudgetReset()
}

func TestToolBudgetBadValueUncapped(t *testing.T) {
	t.Setenv("ANPU_TOOL_BUDGET_SEC", "banana")
	if ToolBudgetLimit() != 0 {
		t.Fatal("unparseable budget must be uncapped")
	}
}

// Phase 4: ToolStatus must be honest — unknown names, embedded
// fallbacks, and installable/manual misses each report distinctly.
func TestToolStatusHonesty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if state, _ := ToolStatus(ctx, "definitely-not-a-tool"); state != ToolMissingManual {
		t.Fatalf("unknown tool must be missing-manual, got %q", state)
	}
	// ffuf has embedded fallbacks (dirs/backupplus): on machines without
	// the binary it must report embedded, never external.
	if _, ok := LookupBinary("ffuf"); ok {
		t.Skip("ffuf installed here — status depends on environment")
	}
	if state, detail := ToolStatus(ctx, "ffuf"); state != ToolEmbedded || !strings.Contains(detail, "dirs") {
		t.Fatalf("ffuf must be embedded with fallback names, got %q %q", state, detail)
	}
	// anew has no fallback and a go recipe → installable.
	if _, ok := LookupBinary("anew"); ok {
		t.Skip("anew installed here — status depends on environment")
	}
	if state, detail := ToolStatus(ctx, "anew"); state != ToolMissingInstallable || !strings.Contains(detail, "go install") {
		t.Fatalf("anew must be missing-installable, got %q %q", state, detail)
	}
}

func TestSpecPrereqsAndCost(t *testing.T) {
	ffuf, _ := SpecByName("ffuf")
	prereqs := SpecPrereqs(ffuf)
	found := false
	for _, p := range prereqs {
		if strings.Contains(p, "ANPU_WORDLIST") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ffuf must require ANPU_WORDLIST, got %v", prereqs)
	}
	if SpecTimeout(ffuf) != 420 {
		t.Fatalf("ffuf timeout must be 420, got %d", SpecTimeout(ffuf))
	}
	worst := LevelWorstCase()
	if worst["advanced"] <= 0 || worst["ultra"] <= worst["advanced"] {
		t.Fatalf("worst-case sums must be positive with ultra > advanced, got %v", worst)
	}
	if FormatDuration(90) != "1m30s" || FormatDuration(45) != "45s" {
		t.Fatal("FormatDuration wrong")
	}
	if got := len(EnvStatus()); got < 7 {
		t.Fatalf("expected 7 env entries, got %d", got)
	}
}
