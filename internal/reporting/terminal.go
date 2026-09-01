package reporting

import (
	"fmt"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
)

const banner = `
        ▄▀█ █▄░█ █▀█ █░█
        █▀█ █░▀█ █▀▀ █▄█
   Web Security Intelligence
`

// PrintBanner prints ANPU's terminal banner and target line.
func PrintBanner(target string) {
	fmt.Print(banner)
	fmt.Printf("\nTarget: %s\n\n", target)
}

// StageLine renders a single "Stage   ✓" / "Stage   ✗" / "Stage   -" line.
func StageLine(label string, done, skipped bool, err error, verbose bool, findings, warnings int) string {
	pad := 18
	name := label
	if len(name) < pad {
		name = name + strings.Repeat(" ", pad-len(name))
	}
	var out string
	switch {
	case err != nil:
		out = fmt.Sprintf("%s✗ (%v)", name, err)
	case skipped:
		out = fmt.Sprintf("%s-", name)
	case done:
		out = fmt.Sprintf("%s✓", name)
	default:
		out = name
	}
	if verbose && done {
		out += fmt.Sprintf("  (+%d findings, %d warnings)", findings, warnings)
	}
	return out
}

// ProgressBar renders a simple textual progress bar.
func ProgressBar(percent int, width int) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := width * percent / 100
	return "[" + strings.Repeat("█", filled) + strings.Repeat(" ", width-filled) + fmt.Sprintf("] %d%%", percent)
}

// PrintResultsSummary prints the terminal summary after a scan completes.
// When quiet is true, info-severity findings are suppressed from terminal
// output; they are still written to JSON/HTML/SARIF reports unchanged.
func PrintResultsSummary(summary *models.ScanSummary, reportPath string, quiet bool) {
	if summary.SeverityCounts == nil {
		summary.RecomputeSeverityCounts()
	}
	fmt.Println("\nResults")
	fmt.Println()
	fmt.Printf("CRITICAL     %d\n", summary.SeverityCounts[models.SeverityCritical])
	fmt.Printf("HIGH         %d\n", summary.SeverityCounts[models.SeverityHigh])
	fmt.Printf("MEDIUM       %d\n", summary.SeverityCounts[models.SeverityMedium])
	fmt.Printf("LOW          %d\n", summary.SeverityCounts[models.SeverityLow])
	if !quiet {
		fmt.Printf("INFO         %d\n", summary.SeverityCounts[models.SeverityInfo])
	}
	fmt.Println()
	fmt.Printf("Risk Score: %.1f/10\n", summary.RiskScore)
	if reportPath != "" {
		fmt.Printf("\nReport:\n%s\n", reportPath)
	}
	if len(summary.Warnings) > 0 {
		fmt.Println("\nNotes:")
		for _, w := range summary.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}
}

// AuthorizationWarning is printed before every scan.
const AuthorizationWarning = `⚠  ANPU performs active network requests against the target.
   Only scan targets you own or are explicitly authorized to test.
   Unauthorized scanning may be illegal in your jurisdiction.
`
