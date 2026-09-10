package reporting

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/anpu-project/anpu/pkg/models"
	"golang.org/x/term"
)

// Palette — dark phosphor theme
const (
	phosphor = "\x1b[38;2;0;255;102m"   // #00FF66
	muted    = "\x1b[38;2;102;102;102m" // #666666
	amber    = "\x1b[38;2;255;176;0m"   // #FFB000
	cyanText = "\x1b[38;2;0;243;255m"   // #00F3FF
	whiteHi  = "\x1b[97m"               // bright white
	boldSeq  = "\x1b[1m"
	bord     = "\x1b[38;2;58;58;58m" // border
	reset    = "\x1b[0m"
	clearSeq = "\x1b[2J\x1b[H"
)

// anpuWordmark is the FIGlet-style "ANPU" block typography, styled and
// recolored in code (amber). The Chafa jackal logo art was retired from
// the display; the source files (anpu_logo.png, banner.txt,
// logo_banner.txt) are kept on disk for reuse.
const anpuWordmark = `  █████╗ ███╗   ██╗██████╗ ██╗   ██╗
 ██╔══██╗████╗  ██║██╔══██╗██║   ██║
 ███████║██╔██╗ ██║██████╔╝██║   ██║
 ██╔══██║██║╚██╗██║██╔═══╝ ██║   ██║
 ██║  ██║██║ ╚████║██║     ╚██████╔╝
 ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝`

const tagline = `G U A R D I A N  │  Web Security Intelligence Engine`

var ansiSeq = regexp.MustCompile("\x1b\\[[0-9;]*m")

// stripANSI removes ANSI color sequences for Plain / non-color terminals.
func stripANSI(s string) string {
	return ansiSeq.ReplaceAllString(s, "")
}

// renderWordmark colors the ANPU block text amber when color is allowed,
// plain ASCII otherwise (callers decide via colorOK).
func renderWordmark(colorOK bool) string {
	if !colorOK {
		return toPlainBlocks(anpuWordmark)
	}
	return boldSeq + amber + anpuWordmark + reset
}

// toPlainBlocks maps block/box-drawing glyphs to ASCII for Plain mode
// and non-color terminals (TERM=dumb, CI logs).
func toPlainBlocks(s string) string {
	r := strings.NewReplacer(
		"█", "#", "▓", "#", "▒", "+", "░", ".",
		"▀", "#", "▄", "#", "▌", "|", "▐", "|",
		"╔", "+", "╗", "+", "╚", "+", "╝", "+",
		"═", "-", "║", "|",
	)
	return r.Replace(s)
}

// BannerOptions controls human-oriented terminal output.
// Silent suppresses banner, stage lines, and the results summary so
// stdout stays clean for pipes (findings go to files or --jsonl).
// Plain forces ASCII stage markers instead of unicode symbols.
type BannerOptions struct {
	Silent   bool
	NoBanner bool
	Plain    bool
}

// IsTerminal reports whether stdout is an interactive terminal
// (as opposed to a pipe or redirect). Used to decide whether
// human-oriented chrome is appropriate.
func IsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// SupportsColor reports whether color output is appropriate.
// Respects NO_COLOR (https://no-color.org) and TERM=dumb.
func SupportsColor() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if strings.ToLower(os.Getenv("TERM")) == "dumb" {
		return false
	}
	return IsTerminal()
}

// ShouldShowBanner reports whether the banner should print.
func ShouldShowBanner(opts BannerOptions) bool {
	if opts.Silent || opts.NoBanner {
		return false
	}
	return true
}

// TerminalWidth returns the terminal width in columns: $COLUMNS first
// (so users and tests can override), then the real console size,
// falling back to 80 when output is piped.
func TerminalWidth() int {
	if c := strings.TrimSpace(os.Getenv("COLUMNS")); c != "" {
		if n, err := strconv.Atoi(c); err == nil && n >= 20 {
			return n
		}
	}
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w >= 20 {
		return w
	}
	return 80
}

// visibleWidth counts characters ignoring ANSI color sequences.
func visibleWidth(s string) int {
	return len([]rune(stripANSI(s)))
}

// centerLine pads s on the left so it sits centered in width.
// Lines wider than width are returned unchanged.
func centerLine(s string, width int) string {
	if w := visibleWidth(s); w < width {
		return strings.Repeat(" ", (width-w)/2) + s
	}
	return s
}

// centerBlock pads every line of a multi-line block by the same amount
// so boxes and shapes keep their alignment while the block centers.
func centerBlock(s string, width int) string {
	lines := strings.Split(s, "\n")
	max := 0
	for _, ln := range lines {
		if w := visibleWidth(ln); w > max {
			max = w
		}
	}
	if max >= width {
		return s
	}
	pad := strings.Repeat(" ", (width-max)/2)
	for i, ln := range lines {
		if ln != "" {
			lines[i] = pad + ln
		}
	}
	return strings.Join(lines, "\n")
}

// PrintBanner prints ANPU's terminal banner and target line.
// Kept for backward compatibility; prefers PrintBannerWithOptions.
func PrintBanner(target string) {
	PrintBannerWithOptions(target, BannerOptions{})
}

// PrintBannerWithOptions prints the banner unless suppressed.
//
// Layout: amber ANPU block typography on top, then the tagline and the
// target line.
func PrintBannerWithOptions(target string, opts BannerOptions) {
	if !ShouldShowBanner(opts) {
		return
	}
	PrintBannerHeader(opts)
	width := TerminalWidth()
	fmt.Printf("\n%s\n\n", centerLine(fmt.Sprintf("Target: %s", target), width))
}

// PrintBannerHeader prints the ANPU wordmark and tagline without the
// target line. Used for the bare `anpu` root help screen, where there
// is no scan target yet. It never clears scrollback — only the live
// scan start clears (see Live.Boot).
func PrintBannerHeader(opts BannerOptions) {
	colorOK := !opts.Plain && SupportsColor()
	wordmark := renderWordmark(colorOK)
	sub := tagline
	if colorOK {
		sub = phosphor + tagline + reset
	} else {
		wordmark = stripANSI(wordmark)
		sub = stripANSI(sub)
	}
	width := TerminalWidth()
	wlines := strings.Split(wordmark, "\n")
	for i, ln := range wlines {
		wlines[i] = centerLine(ln, width)
	}
	fmt.Print(strings.Join(wlines, "\n"))
	fmt.Printf("\n%s\n", centerLine(sub, width))
}

// PrintFirstRunHint prints a short, friendly starter box under the root
// help screen. It gives new and non-technical users one obvious next step
// and frames the authorization rule as guidance, not an error dump.
func PrintFirstRunHint(opts BannerOptions) {
	colorOK := !opts.Plain && SupportsColor()
	var b strings.Builder
	if colorOK {
		b.WriteString("\n" + bord + "  ┌─ New here? ─────────────────────────────" + reset + "\n")
		b.WriteString(bord + "  │  " + reset + "Start with a safe, passive scan:\n")
		b.WriteString(bord + "  │    " + reset + phosphor + "anpu safe https://your-site.com" + reset + "\n")
		b.WriteString(bord + "  │  " + reset + muted + "Only scan systems you own or are" + reset + "\n")
		b.WriteString(bord + "  │  " + reset + muted + "explicitly authorized to test." + reset + "\n")
		b.WriteString(bord + "  └──────────────────────────────────────────" + reset + "\n")
	} else {
		b.WriteString("\n  +-- New here? ------------------------------\n")
		b.WriteString("  |  Start with a safe, passive scan:\n")
		b.WriteString("  |    anpu safe https://your-site.com\n")
		b.WriteString("  |  Only scan systems you own or are\n")
		b.WriteString("  |  explicitly authorized to test.\n")
		b.WriteString("  +------------------------------------------\n")
	}
	fmt.Print(centerBlock(b.String(), TerminalWidth()))
}

// PrintWelcomeMenu prints the numbered launch menu: pick a scan level
// (or past results) instead of typing commands. It pairs with the
// interactive prompt in the root command; each number maps to a real
// subcommand shown in parentheses.
func PrintWelcomeMenu(opts BannerOptions) {
	colorOK := !opts.Plain && SupportsColor()
	q := "What would you like to do?"
	if colorOK {
		q = boldSeq + whiteHi + q + reset
	}
	fmt.Printf("\n%s\n\n", q)
	item := func(num, desc, cmd string) {
		if num == "0" {
			if !colorOK {
				fmt.Printf("  %s) %s\n", num, desc)
				return
			}
			fmt.Printf("  %s%s)%s %s%s%s\n", muted, num, reset, muted, desc, reset)
			return
		}
		if !colorOK {
			fmt.Printf("  %s) %s  (%s)\n", num, desc, cmd)
			return
		}
		fmt.Printf("  %s%s)%s %s  (%s)\n", boldSeq+amber, num, reset, desc, cmd)
	}
	item("1", "Gentle check — read-only probes, never touches data", "safe")
	item("2", "Deeper check — gentle look plus careful tests", "advanced")
	item("3", "Deepest check — finds the most, takes the longest", "ultra")
	item("4", "See your past scans", "history")
	item("5", "Show every command", "help")
	item("0", "Exit", "exit")
	pick := "Pick a number:"
	if colorOK {
		pick = phosphor + pick + reset
	}
	fmt.Printf("\n%s ", pick)
}

// PrintMenuPrompt reprints a short retry prompt after invalid input.
func PrintMenuPrompt(opts BannerOptions) {
	pick := "Pick 1-5 (or 0 to exit):"
	if !opts.Plain && SupportsColor() {
		pick = phosphor + pick + reset
	}
	fmt.Printf("%s ", pick)
}

// helpSectionHeaders are cobra help headings rendered in bold phosphor.
var helpSectionHeaders = map[string]bool{
	"Usage:": true, "Aliases:": true, "Examples:": true,
	"Available Commands:": true, "Additional help topics:": true,
	"Flags:": true, "Global Flags:": true,
}

// isHelpHeading reports whether a help line is a section heading:
// a known cobra heading, or a command-group title ("Check a website:").
func isHelpHeading(line, trimmed string) bool {
	if helpSectionHeaders[trimmed] {
		return true
	}
	if line == trimmed && strings.HasSuffix(trimmed, ":") {
		if r := []rune(trimmed); len(r) > 2 && r[0] >= 'A' && r[0] <= 'Z' {
			return true
		}
	}
	return false
}

var helpCmdRow = regexp.MustCompile(`^(\s+)(\S+)(.*)$`)

// helpFlagDef matches the flag definition part of a flag row
// ("  -h, --help" in "  -h, --help            help for anpu").
var helpFlagDef = regexp.MustCompile(`^(\s+)(-\S.*?)(\s{2,}.*)?$`)

// ColorizeHelp paints cobra help text for color terminals: green section
// headings, amber command names, cyan flag definitions, bright-white
// description, amber authorization note. Non-color terminals and
// --plain get the text unchanged.
func ColorizeHelp(text string, opts BannerOptions) string {
	return colorizeHelpText(text, !opts.Plain && SupportsColor())
}

func colorizeHelpText(text string, colorOK bool) string {
	if !colorOK {
		return text
	}
	lines := strings.Split(text, "\n")
	section := "long"
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if isHelpHeading(ln, trimmed) {
			lines[i] = boldSeq + phosphor + ln + reset
			switch trimmed {
			case "Usage:":
				section = "usage"
			case "Available Commands:":
				section = "commands"
			case "Flags:", "Global Flags:":
				section = "flags"
			default:
				// Command-group titles keep the commands section active.
				if section != "commands" {
					section = "other"
				}
			}
			continue
		}
		if strings.HasPrefix(trimmed, `Use "`) {
			lines[i] = muted + ln + reset
			continue
		}
		switch section {
		case "long":
			if trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, "ANPU must only") {
				lines[i] = amber + ln + reset
			} else {
				lines[i] = whiteHi + ln + reset
			}
		case "usage":
			if trimmed != "" {
				lines[i] = whiteHi + ln + reset
			}
		case "commands":
			if m := helpCmdRow.FindStringSubmatch(ln); m != nil {
				lines[i] = m[1] + boldSeq + amber + m[2] + reset + m[3]
			}
		case "flags":
			if m := helpFlagDef.FindStringSubmatch(ln); m != nil {
				lines[i] = m[1] + cyanText + m[2] + reset + m[3]
			}
		}
	}
	return strings.Join(lines, "\n")
}

// PrintAuthorizationWarning writes the authorization notice to stderr
// so stdout stays clean for piped machine output.
func PrintAuthorizationWarning() {
	fmt.Fprint(os.Stderr, AuthorizationWarning)
}

// StageLine renders a single "Stage   ✓" / "Stage   ✗" / "Stage   -" line.
func StageLine(label string, done, skipped bool, err error, verbose bool, findings, warnings int) string {
	return StageLineWithOptions(label, done, skipped, err, verbose, findings, warnings, BannerOptions{}, "")
}

// StageLineWithOptions renders a stage line — aligned, muted for skipped.
// reason annotates skipped lines (quiet-skip gates); empty keeps the bare dash.
func StageLineWithOptions(label string, done, skipped bool, err error, verbose bool, findings, warnings int, opts BannerOptions, reason string) string {
	pad := 15
	name := label
	if len(name) < pad {
		name = name + strings.Repeat(" ", pad-len(name))
	}
	plain := opts.Plain || !SupportsColor()
	// Palette
	cOk, cFail, cSkip, cMute, rst := "", "", "", "", ""
	if !plain && SupportsColor() {
		cOk = phosphor
		cFail = "\x1b[38;2;255;59;59m"
		cSkip = muted
		cMute = muted
		rst = reset
	}
	var out string
	plainMark := plain
	switch {
	case err != nil:
		mark := "[✗]"
		if plainMark {
			mark = "[!!]"
		}
		out = fmt.Sprintf("%s%s%s %s  %s%v%s", cFail, mark, rst, name, cMute, err, rst)
	case skipped:
		mark := "[─]"
		if plainMark {
			mark = "[--]"
		}
		rsn := "—"
		if strings.TrimSpace(reason) != "" {
			rsn = reason
			if len(rsn) > 60 {
				rsn = rsn[:57] + "..."
			}
		}
		out = fmt.Sprintf("%s%s%s %s  %s%s%s", cSkip, mark, rst, name, cMute, rsn, rst)
	case done:
		mark := "[✓]"
		if plainMark {
			mark = "[ok]"
		}
		if findings > 0 {
			mark = "[!]"
			if plainMark {
				mark = "[!!]"
			} else {
				cOk = amber
			}
		}
		out = fmt.Sprintf("%s%s%s %s", cOk, mark, rst, name)
		if findings > 0 {
			out += fmt.Sprintf("  %s+%d%s", cOk, findings, rst)
		}
	default:
		out = name
	}
	if verbose && done {
		out += fmt.Sprintf("  %s(+%d findings)%s", cMute, findings, rst)
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
	PrintResultsSummaryWithOptions(summary, reportPath, quiet, BannerOptions{})
}

// PrintResultsSummaryWithOptions skips all human output when Silent is set.
func PrintResultsSummaryWithOptions(summary *models.ScanSummary, reportPath string, quiet bool, opts BannerOptions) {
	if opts.Silent {
		return
	}
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
	if summary.SuppressedByConfidence > 0 {
		fmt.Printf("Suppressed: %d finding(s) below --min-confidence threshold\n", summary.SuppressedByConfidence)
	}
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
const AuthorizationWarning = `[!] ANPU performs active network requests against the target.
    Only scan targets you own or are explicitly authorized to test.
    Unauthorized scanning may be illegal in your jurisdiction.
`
