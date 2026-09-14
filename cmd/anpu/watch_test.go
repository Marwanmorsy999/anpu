package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/internal/diff"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestPrintWatchDiffShowsRemovals(t *testing.T) {
	result := &diff.Result{
		FindingsAdded: 1, EndpointsRemoved: 1, TechnologiesRemoved: 1,
		Findings: []diff.FindingChange{
			{Finding: models.Finding{Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Title: "New hole", URL: "https://x/n"}, Kind: "added"},
			{Finding: adFinding(), Kind: "removed"},
		},
		Endpoints:    []diff.EndpointChange{{Endpoint: models.Endpoint{URL: "https://x/gone"}, Kind: "removed"}},
		Technologies: []diff.TechnologyChange{{Technology: models.Technology{Name: "OldCMS", Version: "1.0"}, Kind: "removed"}},
	}
	out := captureStdout(t, func() { printWatchDiff(result) })
	for _, want := range []string{"+ NEW", "- FIXED", "removed endpoint(s)", "https://x/gone", "removed technolog", "OldCMS"} {
		if !strings.Contains(out, want) {
			t.Fatalf("watch diff must show %q:\n%s", want, out)
		}
	}
}

func adFinding() models.Finding {
	return models.Finding{Severity: models.SeverityLow, Confidence: models.ConfidenceLow, Title: "Fixed thing"}
}

func TestPrintWatchDiffTechChanged(t *testing.T) {
	result := &diff.Result{
		Technologies: []diff.TechnologyChange{{
			Technology: models.Technology{Name: "CMS", Version: "2.0"},
			Previous:   models.Technology{Name: "CMS", Version: "1.0"},
			Kind:       "changed",
		}},
	}
	out := captureStdout(t, func() { printWatchDiff(result) })
	if !strings.Contains(out, "1.0") || !strings.Contains(out, "2.0") {
		t.Fatalf("tech version change must show both versions:\n%s", out)
	}
}

func TestPrintWatchDiffQuiet(t *testing.T) {
	out := captureStdout(t, func() { printWatchDiff(&diff.Result{}) })
	if !strings.Contains(out, "no changes") {
		t.Fatalf("empty diff must print quiet line:\n%s", out)
	}
}

func TestWatchHasSeverityAtOrAbove(t *testing.T) {
	result := &diff.Result{
		Findings: []diff.FindingChange{
			{Finding: adFinding(), Kind: "added"},
			{Finding: models.Finding{Severity: models.SeverityCritical}, Kind: "removed"},
		},
	}
	if watchHasSeverityAtOrAbove(result, models.SeverityMedium) {
		t.Fatal("low added must not trip medium gate")
	}
	if !watchHasSeverityAtOrAbove(result, models.SeverityLow) {
		t.Fatal("low added must trip low gate")
	}
	// Removed criticals never trip: only added findings gate.
	if watchHasSeverityAtOrAbove(&diff.Result{
		Findings: []diff.FindingChange{{Finding: models.Finding{Severity: models.SeverityCritical}, Kind: "removed"}},
	}, models.SeverityLow) {
		t.Fatal("removed findings must not trip the gate")
	}
}
