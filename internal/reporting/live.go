package reporting

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/anpu-project/anpu/pkg/models"
	"github.com/anpu-project/anpu/pkg/version"
)

// Live renders an "alive" scan session — Phases 1-4.
type Live struct {
	mu       sync.Mutex
	out      io.Writer
	plain    bool
	enabled  bool
	verbose  bool
	order    []string
	pos      int
	current  string
	started  time.Time
	stop     chan struct{}
	wg       sync.WaitGroup
	hits     int
	interval time.Duration
	// tracker prints each pipeline phase header once
	tracker PhaseTracker
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
var asciiFrames = []string{"|", "/", "-", "\\"}

type LiveStage struct {
	Label       string
	Done        bool
	Skipped     bool
	Reason      string
	Err         error
	NewFindings int
	Warnings    int
	// Phase is the pipeline phase ("foundation", "discovery",
	// "targeted", "active"); empty means no header tracking.
	Phase string
}

// phaseTitles renders pipeline phase headers.
var phaseTitles = map[string]string{
	"foundation": "Phase 1 · Foundation — passive intel",
	"discovery":  "Phase 2 · Discovery — endpoints, crawlers, enumerators",
	"targeted":   "Phase 3 · Targeted — probing discovered surface",
	"active":     "Phase 4 · Active — differentials and confirmations",
}

// PhaseTracker prints each pipeline phase header once per scan.
type PhaseTracker struct{ seen map[string]bool }

// Header returns the formatted header for phase, or "" when the phase
// is unknown, empty, or already announced.
func (t *PhaseTracker) Header(phase string, opts BannerOptions) string {
	title, ok := phaseTitles[phase]
	if !ok || phase == "" {
		return ""
	}
	if t.seen == nil {
		t.seen = map[string]bool{}
	}
	if t.seen[phase] {
		return ""
	}
	t.seen[phase] = true
	useColor := !opts.Plain && SupportsColor()
	if !useColor {
		return "── " + title
	}
	return muted + "── " + reset + phosphor + title + reset
}

func NewLive(out io.Writer, opts BannerOptions) *Live {
	return &Live{
		out:      out,
		plain:    opts.Plain,
		enabled:  !opts.Silent && isTerminalWriter(out),
		verbose:  false,
		stop:     make(chan struct{}),
		interval: 120 * time.Millisecond,
	}
}

// SetVerbose enables per-stage skip lines (otherwise skips are aggregated)
func (l *Live) SetVerbose(v bool) { l.verbose = v }

func (l *Live) Expect(stages []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.order = append([]string(nil), stages...)
}

func ansiVisibleLen(s string) int {
	// strip \x1b[...m
	vis := 0
	inEsc := false
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			inEsc = true
			i += 2
			continue
		}
		if inEsc {
			if s[i] == 'm' {
				inEsc = false
			}
			i++
			continue
		}
		vis++
		i++
	}
	return vis
}

func (l *Live) Boot(target, profile string, n int) {
	if !l.showChrome() {
		return
	}
	// Live scan start is the only place that clears scrollback for a
	// focused canvas. --help and banner paths never clear.
	if !l.plain && SupportsColor() {
		_, _ = fmt.Fprint(l.out, clearSeq)
	}
	useColor := !l.plain && SupportsColor()
	b, m, p, r := "", "", "", ""
	dim := ""
	if useColor {
		b = bord
		m = muted
		p = phosphor
		r = reset
		dim = "\x1b[2m"
	}
	inner := 78
	if ansiVisibleLen(target) > 52 {
		inner = 88
	}
	top := b + "┌" + strings.Repeat("─", inner) + "┐" + r
	bot := b + "└" + strings.Repeat("─", inner) + "┘" + r
	// line 1: Target — prefix "  Target: " is 10 visible cols.
	const prefix1Len = 10
	tLine := p + target + r
	if ansiVisibleLen(tLine) > inner-prefix1Len {
		// truncate visible, keep color wrappers
		cutLen := inner - prefix1Len - 3
		if cutLen < 10 {
			cutLen = 10
		}
		if cutLen > len(target) {
			cutLen = len(target)
		}
		// naive truncate on bytes, but target is ASCII URL so safe
		tLine = p + target[:cutLen] + "..." + r
	}
	pad1 := inner - prefix1Len - ansiVisibleLen(tLine)
	if pad1 < 0 {
		pad1 = 0
	}
	// line 2: PROFILE · N stages · Engine
	// "  Profile: " (11) + prof + "  ·  " (5) + stages + "  ·  " (5) + version
	profUpper := strings.ToUpper(profile)
	stageStr := fmt.Sprintf("%d stages", n)
	line2ContentVis := 11 + ansiVisibleLen(profUpper) + 5 + ansiVisibleLen(stageStr) + 5 + len(version.Version)
	_ = dim
	pad2 := inner - line2ContentVis
	if pad2 < 0 {
		pad2 = 0
	}
	_, _ = fmt.Fprintln(l.out, "")
	_, _ = fmt.Fprintln(l.out, top)
	_, _ = fmt.Fprintln(l.out, b+"│"+r+"  Target: "+tLine+strings.Repeat(" ", pad1)+b+"│"+r)
	_, _ = fmt.Fprintln(l.out, b+"│"+r+"  Profile: "+m+profUpper+r+"  "+dim+"·"+r+"  "+stageStr+"  "+dim+"·"+r+"  "+version.Version+strings.Repeat(" ", pad2)+b+"│"+r)
	_, _ = fmt.Fprintln(l.out, bot)
}

func (l *Live) StageDone(s LiveStage) {
	if !l.showChrome() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopTickerLocked()
	if h := l.tracker.Header(s.Phase, BannerOptions{Plain: l.plain}); h != "" {
		_, _ = fmt.Fprintln(l.out, h)
	}
	if s.Skipped {
		_, _ = fmt.Fprintln(l.out, l.finishLineLocked(s))
		l.pos++
		l.startNextLocked()
		return
	}
	line := l.finishLineLocked(s)
	l.current = ""
	if s.Done {
		l.hits += s.NewFindings
	}
	_, _ = fmt.Fprintln(l.out, line)
	l.pos++
	l.startNextLocked()
	if s.Done && s.NewFindings > 0 {
		prefix := "  " + muted + "├──" + reset
		am, rs, mu := amber, reset, muted
		if l.plain || !SupportsColor() {
			prefix = "  |--"
			am, rs, mu = "", "", ""
		}
		_, _ = fmt.Fprintf(l.out, "%s %s[!]%s +%d %s\n", prefix, am, rs, s.NewFindings, mu+"finding(s)"+rs)
	}
}

func (l *Live) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopTickerLocked()
	if l.current != "" {
		_, _ = fmt.Fprint(l.out, "\r"+strings.Repeat(" ", 80)+"\r")
		l.current = ""
	}
}

func (l *Live) Panel(summary *models.ScanSummary, reportPath string, quiet bool, opts BannerOptions) {
	if opts.Silent {
		return
	}
	if summary.SeverityCounts == nil {
		summary.RecomputeSeverityCounts()
	}
	c := summary.SeverityCounts
	top := topFinding(summary.Findings)
	useColor := !opts.Plain && SupportsColor()
	// Palette
	ph := ""
	am := ""
	mu := ""
	gr := ""
	rd := ""
	rs := ""
	if useColor {
		ph = phosphor
		am = amber
		mu = muted
		gr = "\x1b[90m"
		rd = "\x1b[38;2;255;59;59m"
		rs = reset
	} else {
		ph, am, mu, gr, rd = "", "", "", "", ""
		rs = ""
	}
	_, _ = fmt.Fprintln(l.out, "")
	// Summary Matrix
	_, _ = fmt.Fprintf(l.out, "%s  %sGRADE %s%s  %s(%.1f/10)%s  ", mu, ph, RiskGrade(summary.RiskScore), rs, mu, summary.RiskScore, rs)
	_, _ = fmt.Fprintf(l.out, "%sCRITICAL %d%s  %sHIGH %d%s  %sMEDIUM %d%s  %sLOW %d%s",
		rd, c[models.SeverityCritical], rs,
		am, c[models.SeverityHigh], rs,
		am, c[models.SeverityMedium], rs,
		gr, c[models.SeverityLow], rs)
	if quiet {
		_, _ = fmt.Fprintf(l.out, "  %sInfo suppressed%s", mu, rs)
	} else {
		_, _ = fmt.Fprintf(l.out, "  %sInfo %d%s", mu, c[models.SeverityInfo], rs)
	}
	_, _ = fmt.Fprintln(l.out, "")
	if top != nil {
		t := top.Title
		if len(t) > 68 {
			t = t[:65] + "..."
		}
		_, _ = fmt.Fprintf(l.out, "  %sTop:%s %s %s[%s %.1f]%s\n", mu, rs, t, mu, strings.ToUpper(string(top.Severity)), top.RiskScore, rs)
	} else {
		_, _ = fmt.Fprintf(l.out, "  %sTop:%s nominal\n", mu, rs)
	}
	if reportPath != "" {
		rep := reportPath
		if len(rep) > 78 {
			rep = "..." + rep[len(rep)-75:]
		}
		_, _ = fmt.Fprintf(l.out, "  %sReport:%s %s\n", mu, rs, rep)
	}
	if summary.SuppressedByConfidence > 0 {
		_, _ = fmt.Fprintf(l.out, "  %sNote:%s %d finding(s) below --min-confidence\n", mu, rs, summary.SuppressedByConfidence)
	}
	if len(summary.CodeFindings) > 0 {
		_, _ = fmt.Fprintf(l.out, "  %sLocal code:%s %d finding(s) in unscored appendix (not the target, excluded from grade)\n", mu, rs, len(summary.CodeFindings))
	}
	if len(summary.PhaseTimings) > 0 {
		parts := make([]string, 0, len(summary.PhaseTimings))
		for _, pt := range summary.PhaseTimings {
			parts = append(parts, fmt.Sprintf("%s %.0fs/%d", pt.Phase, pt.Seconds, pt.Stages))
		}
		_, _ = fmt.Fprintf(l.out, "  %sPhases:%s %s\n", mu, rs, strings.Join(parts, "  ·  "))
	}
	if len(summary.SlowestStages) > 0 {
		parts := make([]string, 0, len(summary.SlowestStages))
		for _, st := range summary.SlowestStages {
			parts = append(parts, fmt.Sprintf("%s %.1fs", st.Stage, st.Seconds))
		}
		_, _ = fmt.Fprintf(l.out, "  %sSlowest:%s %s\n", mu, rs, strings.Join(parts, "  ·  "))
	}
	if len(summary.Warnings) > 0 {
		// Filter out optional-tool noise — those are in next-steps, not warnings
		var filtered []string
		for _, w := range summary.Warnings {
			if strings.Contains(w, "scanner unavailable") || strings.Contains(w, "commoncrawl history unavailable:") || strings.Contains(w, "wayback history unavailable:") {
				continue
			}
			filtered = append(filtered, w)
		}
		if len(filtered) > 0 {
			_, _ = fmt.Fprintf(l.out, "  %sNotes:%s\n", mu, rs)
			for _, w := range filtered {
				_, _ = fmt.Fprintf(l.out, "   %s·%s %s\n", mu, rs, w)
			}
		}
	}
	// Missing-tool guidance lives in `anpu tools` (per-tool status +
	// install hints), not here: every skipped stage already prints its
	// own reason on its stage line.
	_, _ = fmt.Fprintln(l.out, "")
}

func StaticStageLine(s LiveStage, opts BannerOptions) string {
	return StageLineWithOptions(s.Label, s.Done, s.Skipped, s.Err, false, s.NewFindings, s.Warnings, opts, s.Reason)
}

func (l *Live) Animated() bool { return l.enabled }

func (l *Live) showChrome() bool { return l.enabled }

func (l *Live) startNextLocked() {
	if l.pos >= len(l.order) {
		return
	}
	l.current = l.order[l.pos]
	l.started = time.Now()
	l.stop = make(chan struct{})
	l.wg.Add(1)
	go l.tick(l.current, l.started, l.stop)
}

func (l *Live) stopTickerLocked() {
	if l.current == "" {
		return
	}
	select {
	case <-l.stop:
	default:
		close(l.stop)
	}
	_, _ = fmt.Fprint(l.out, "\r"+strings.Repeat(" ", 80)+"\r")
}

func (l *Live) tick(label string, start time.Time, stop chan struct{}) {
	defer l.wg.Done()
	i := 0
	t := time.NewTicker(l.interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			l.mu.Lock()
			if l.current != label {
				l.mu.Unlock()
				return
			}
			el := time.Since(start).Truncate(100 * time.Millisecond)
			useColor := !l.plain && SupportsColor()
			frames := spinnerFrames
			if l.plain {
				frames = asciiFrames
			}
			sp := frames[i%len(frames)]
			if useColor {
				sp = muted + sp + reset
			}
			// Column aligned: %-15s
			_, _ = fmt.Fprintf(l.out, "\r  %-15s %s %s", label, sp, el)
			l.mu.Unlock()
			i++
		}
	}
}

func (l *Live) finishLineLocked(s LiveStage) string {
	name := fmt.Sprintf("%-15s", s.Label)
	useColor := !l.plain && SupportsColor()
	cyan := ""
	green := ""
	yellow := ""
	gray := ""
	red := ""
	resetC := ""
	if useColor {
		cyan = "\x1b[36m"
		green = phosphor
		yellow = amber
		gray = muted
		red = "\x1b[38;2;255;59;59m"
		resetC = reset
	}
	switch {
	case s.Err != nil:
		msg := s.Err.Error()
		if len(msg) > 44 {
			msg = msg[:41] + "..."
		}
		mark := "[✗]"
		if l.plain {
			mark = "[!!]"
		}
		return fmt.Sprintf("  %s%s%s %s  %s%s%s", red, mark, resetC, name, gray, msg, resetC)
	case s.Skipped:
		reason := s.Reason
		if reason == "" {
			reason = "—"
		} else if len(reason) > 38 {
			reason = reason[:35] + "..."
		}
		mark := "[─]"
		if l.plain {
			mark = "[--]"
		}
		return fmt.Sprintf("  %s%s%s %s  %s%s%s", gray, mark, resetC, name, gray, reason, resetC)
	default:
		el := time.Since(l.started).Truncate(100 * time.Millisecond)
		if l.current == "" {
			el = 0
		}
		mark := "[✓]"
		if l.plain {
			mark = "[ok]"
		}
		mark = fmt.Sprintf("%s%s%s", green, mark, resetC)
		detail := fmt.Sprintf("%s%4s%s", gray, el, resetC)
		if s.NewFindings > 0 {
			fMark := "[!]"
			if l.plain {
				fMark = "[!!]"
			}
			detail = fmt.Sprintf("%s%4s  %s%s +%d%s", gray, el, yellow, fMark, s.NewFindings, resetC)
		}
		return fmt.Sprintf("  %s %-15s  %s", mark, cyan+name+resetC, detail)
	}
}

func topFinding(fs []models.Finding) *models.Finding {
	var top *models.Finding
	for i := range fs {
		if fs[i].Severity == models.SeverityInfo {
			continue
		}
		if top == nil || fs[i].RiskScore > top.RiskScore {
			top = &fs[i]
		}
	}
	return top
}

func isTerminalWriter(w io.Writer) bool {
	_ = w
	return IsTerminal()
}
