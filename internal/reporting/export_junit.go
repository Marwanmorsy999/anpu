// Package reporting — export_junit.go: JUnit XML renderer for CI
// systems that consume testsuites/testsuite/testcase (Jenkins, GitLab,
// Azure DevOps). One testsuite per scan, one testcase per finding,
// sorted worst-first like every other export. Pure function over
// ScanSummary (unit-tested, no I/O beyond the target path).
package reporting

import (
	"encoding/xml"
	"fmt"
	"os"
	"sort"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// junitFailure marks medium-and-above findings as failures. Low/info
// findings stay listed as passing testcases with their evidence in
// system-out: the --fail-on flag (not this file) owns gating policy,
// and low/info items are signal worth keeping, not failures.
type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

type junitTestcase struct {
	Classname string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
}

type junitSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Testcases []junitTestcase `xml:"testcase"`
}

// junitIsFailure reports whether a finding fails the suite.
func junitIsFailure(f models.Finding) bool {
	return f.Severity.Rank() >= models.SeverityMedium.Rank()
}

// junitCase flattens one finding (pure, tested).
func junitCase(f models.Finding) junitTestcase {
	tc := junitTestcase{
		Classname: string(f.Category),
		Name:      fmt.Sprintf("[%s] %s", f.Severity, f.Title),
		SystemOut: fmt.Sprintf("id: %s\nurl: %s\nconfidence: %s\nsource: %s\nevidence: %s",
			f.ID, f.URL, f.Confidence, f.Source, f.Evidence.Observed),
	}
	if junitIsFailure(f) {
		tc.Failure = &junitFailure{
			Message: fmt.Sprintf("%s %s: %s", f.Severity, f.Category, f.Title),
			Type:    string(f.Severity),
			Content: fmt.Sprintf("cwe: %s\nurl: %s\n%s", f.CWE, f.URL, f.Description),
		}
	}
	return tc
}

// WriteJUnit writes findings as JUnit XML (one testsuite per scan).
func WriteJUnit(summary *models.ScanSummary, path string) error {
	fs := append([]models.Finding(nil), summary.Findings...)
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		return fs[i].ID < fs[j].ID
	})
	suite := junitSuite{Name: fmt.Sprintf("anpu scan %s", summary.Target)}
	for _, f := range fs {
		suite.Testcases = append(suite.Testcases, junitCase(f))
		if junitIsFailure(f) {
			suite.Failures++
		}
	}
	suite.Tests = len(suite.Testcases)
	data, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return err
	}
	data = append([]byte(xml.Header), data...)
	return os.WriteFile(path, data, 0o600) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
}
