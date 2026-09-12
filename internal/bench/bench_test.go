package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// The shipped ground truth must always parse: this keeps the contract
// file and the harness in sync. Skipped when the fixture branch (P2-2)
// has not merged yet; mandatory once both are on main.
func TestLoadShippedGroundTruth(t *testing.T) {
	p := filepath.Join("..", "..", "tests", "bench", "ground-truth.yml")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		t.Skip("ground truth fixture not present (P2-2 unmerged)")
	}
	gt, err := LoadGroundTruth(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(gt.Signals) != 5 {
		t.Fatalf("expected 5 signals, got %d", len(gt.Signals))
	}
	ids := map[string]bool{}
	for _, s := range gt.Signals {
		ids[s.ID] = true
	}
	for _, want := range []string{"weak-headers", "exposed-env", "backup-zip", "reflected-xss", "open-redirect"} {
		if !ids[want] {
			t.Fatalf("missing signal %q", want)
		}
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gt.yml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadGroundTruthRejects(t *testing.T) {
	bad := map[string]string{
		"version":  "version: 2\nsignals:\n  - id: a\n    match: {title_contains: x}\n",
		"empty":    "version: 1\nsignals: []\n",
		"dup":      "version: 1\nsignals:\n  - id: a\n    match: {title_contains: x}\n  - id: a\n    match: {title_contains: y}\n",
		"no-id":    "version: 1\nsignals:\n  - match: {title_contains: x}\n",
		"no-match": "version: 1\nsignals:\n  - id: a\n",
		"bad-exp":  "version: 1\nsignals:\n  - id: a\n    match: {title_contains: x}\n    profiles: {safe: sometimes}\n",
		"bad-yaml": "version: [1\n",
		"missing":  "",
	}
	for name, content := range bad {
		p := writeTemp(t, content)
		if name == "missing" {
			p = filepath.Join(t.TempDir(), "nope.yml")
		}
		if _, err := LoadGroundTruth(p); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

func TestMatches(t *testing.T) {
	f := models.Finding{Title: "Exposed environment file (/.env)", Category: models.Category("information-exposure"), URL: "http://x/.env"}
	sig := Signal{ID: "s", Match: MatchRule{TitleContains: "exposed ENVIRONMENT", Category: "information-exposure"}, Path: "/.env"}
	if !matches(f, sig) {
		t.Fatal("case-insensitive title + category + signal path must match")
	}
	sig.Match.Category = "tls"
	if matches(f, sig) {
		t.Fatal("wrong category must not match")
	}
	sig.Match.Category = ""
	sig.Path = "/other"
	if matches(f, sig) {
		t.Fatal("wrong path must not match")
	}
	sig.Path = ""
	sig.Match.Path = "/.env"
	if !matches(f, sig) {
		t.Fatal("match-level path must work when signal path is empty")
	}
}

func TestEvaluateVerdicts(t *testing.T) {
	gt := &GroundTruth{Version: 1, Signals: []Signal{
		{ID: "a", Match: MatchRule{TitleContains: "alpha"}, Profiles: map[string]string{"safe": ExpectHit}},
		{ID: "b", Match: MatchRule{TitleContains: "beta"}, Profiles: map[string]string{"safe": ExpectMiss}},
		{ID: "c", Match: MatchRule{TitleContains: "gamma"}, Profiles: map[string]string{"safe": ExpectHit}},
		{ID: "d", Match: MatchRule{TitleContains: "delta"}, Profiles: map[string]string{"safe": ExpectMiss}},
	}}
	rep := &models.ScanSummary{Findings: []models.Finding{
		{ID: "1", Title: "Alpha hit", Category: "tls", Confidence: models.ConfidenceHigh, URL: "http://x/"},
		{ID: "2", Title: "Delta surprise", Category: "tls", Confidence: models.ConfidenceLow, URL: "http://x/"},
		{ID: "3", Title: "Unrelated noise", Category: "tls", Confidence: models.ConfidenceMedium, URL: "http://x/"},
	}}
	res := Evaluate(rep, gt, "safe")
	if res.Total != 3 || res.Confirmed != 1 || res.Unconfirmed != 2 {
		t.Fatalf("counts wrong: %+v", res)
	}
	byID := map[string]SignalOutcome{}
	for _, o := range res.Signals {
		byID[o.SignalID] = o
	}
	if byID["a"].Verdict != VerdictOK || byID["a"].Outcome != OutcomeHIT {
		t.Fatalf("a must be ok/HIT: %+v", byID["a"])
	}
	if byID["b"].Verdict != VerdictOK || byID["b"].Outcome != OutcomeMISS {
		t.Fatalf("b must be ok/MISS: %+v", byID["b"])
	}
	if byID["c"].Verdict != VerdictMISS {
		t.Fatalf("c must be MISS: %+v", byID["c"])
	}
	if byID["d"].Verdict != VerdictSurpriseHit {
		t.Fatalf("d must be surprise-hit: %+v", byID["d"])
	}
	// Unknown profile defaults to expected hit.
	res2 := Evaluate(rep, gt, "ultra")
	for _, o := range res2.Signals {
		if o.Expected != ExpectHit {
			t.Fatalf("unknown profile must default to hit: %+v", o)
		}
	}
	if len(res.Unmatched) != 1 || res.Unmatched[0].ID != "3" {
		t.Fatalf("unmatched must be [3]: %+v", res.Unmatched)
	}
	// Gate defaults true.
	for _, o := range res.Signals {
		if !o.Gated {
			t.Fatalf("gate must default true: %+v", o)
		}
	}
}

func TestRenderMarkdownDeterministic(t *testing.T) {
	mk := func() []ProfileResult {
		return []ProfileResult{{
			Profile: "safe", Total: 2, Confirmed: 1, Unconfirmed: 1,
			ByCategory: map[string]int{"tls": 2},
			Signals: []SignalOutcome{
				{SignalID: "a", Description: "first", Expected: ExpectHit, Outcome: OutcomeHIT, Verdict: VerdictOK, Gated: true},
				{SignalID: "b", Description: "flaky", Expected: ExpectHit, Outcome: OutcomeMISS, Verdict: VerdictMISS, Gated: false},
			},
		}}
	}
	a, b := RenderMarkdown(mk(), "http://x", []string{"safe"}, 1), RenderMarkdown(mk(), "http://x", []string{"safe"}, 1)
	if a != b {
		t.Fatal("markdown must be deterministic")
	}
	for _, want := range []string{"| Signal | safe |", "✓ HIT", "✗ MISS", "†", "unmatched", "anpu bench"} {
		if !strings.Contains(a, want) {
			t.Fatalf("markdown missing %q:\n%s", want, a)
		}
	}
}

func TestCheckAndRefreshSection(t *testing.T) {
	p := filepath.Join(t.TempDir(), "doc.md")
	doc := "# Title\n\n" + MarkerStart + "\nold table\n" + MarkerEnd + "\n\nProse.\n"
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSection(p, "old table"); err != nil {
		t.Fatalf("matching section must pass: %v", err)
	}
	if err := CheckSection(p, "new table"); err == nil {
		t.Fatal("drifted section must fail")
	}
	if err := RefreshSection(p, "new table"); err != nil {
		t.Fatal(err)
	}
	if err := CheckSection(p, "new table"); err != nil {
		t.Fatalf("refreshed section must pass: %v", err)
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), "Prose.") || !strings.Contains(string(raw), MarkerStart) {
		t.Fatalf("refresh must preserve prose and markers:\n%s", raw)
	}
	noMarkers := filepath.Join(t.TempDir(), "plain.md")
	_ = os.WriteFile(noMarkers, []byte("no markers here\n"), 0o600)
	if err := CheckSection(noMarkers, "x"); err == nil {
		t.Fatal("missing markers must error")
	}
	if err := CheckSection(filepath.Join(t.TempDir(), "missing.md"), "x"); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestCheckIgnoresFindingCounts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "doc.md")
	inner := "| Signal | safe |\n| --- | --- |\n| `a` | ✓ HIT |\n" +
		"Findings (safe): 12 total (9 confirmed / 3 unconfirmed), 11 unmatched."
	base := MarkerStart + "\n" + inner + "\n" + MarkerEnd + "\n"
	if err := os.WriteFile(p, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	// Same verdicts, different counts: must still pass.
	drifted := "| Signal | safe |\n| --- | --- |\n| `a` | ✓ HIT |\n" +
		"Findings (safe): 8 total (5 confirmed / 3 unconfirmed), 7 unmatched."
	if err := CheckSection(p, drifted); err != nil {
		t.Fatalf("count-only drift must pass: %v", err)
	}
	// Changed verdict: must fail.
	changed := strings.Replace(drifted, "✓ HIT", "✗ MISS", 1)
	if err := CheckSection(p, changed); err == nil {
		t.Fatal("verdict drift must fail")
	}
}

func TestRenderJSON(t *testing.T) {
	out, err := RenderJSON(Report{Target: "http://x", Runs: 1, Records: []RunRecord{{
		Profile: "safe", DurationSeconds: 1.5, Result: ProfileResult{Profile: "safe"},
	}}})
	if err != nil || !strings.Contains(out, `"duration_seconds": 1.5`) {
		t.Fatalf("bad json: %q %v", out, err)
	}
}
