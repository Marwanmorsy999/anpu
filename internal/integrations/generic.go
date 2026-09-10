// Package integrations — generic.go: data-driven external-tool runner.
//
// Every Wave 2 free-binary wrapper (items 51-134) runs through
// GenericScanner: resolve binary (warn-and-skip when absent, never
// fatal), expand argument templates, enforce timeout + output caps,
// then normalize real output into Findings/Endpoints/Technologies.
// Per-tool JSON shapes get best-effort structured parsing; everything
// else is mined for URLs/hosts plus a summary finding with the exact
// repro command. No output is ever fabricated: unparseable output
// still yields the summary + mined artifacts, never fake vulns.
//
// Safety: read-only flags are baked into each spec; Adversarial specs
// refuse to run without Modules.Adversarial (--adversarial
// --confirm-authorized); fuzzers need ANPU_WORDLIST (or a bundled
// wordlists/*.txt default); code tools need ANPU_CODE_DIR; mass
// resolvers need ANPU_RESOLVERS. Missing prerequisites warn-and-skip.
package integrations

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// Stdin modes for tools that read targets from standard input.
const (
	StdinNone   = ""
	StdinHost   = "host"    // scan target hostname
	StdinTarget = "target"  // scan target URL
	StdinURLs   = "urllist" // target URL + up to 9 same-host endpoints
)

// Output and safety caps.
const (
	maxToolOutput  = 2 << 20 // 2MB stdout cap per tool
	maxMinedURLs   = 40
	maxMinedHosts  = 40
	maxVerifyDNS   = 20
	maxToolFinds   = 10
	defaultTimeout = 240
)

// AutoInstallEnabled makes missing binaries self-provision: Available
// reports true and Run installs (go/pipx/docker, fail-soft otherwise)
// before executing. Set from --auto-install / scan.auto_install.
// Default false — scans never download anything unasked.
var AutoInstallEnabled bool

// UnsafeEnabled is the operator master override (--unsafe): skips
// --confirm-authorized, lifts safe-purity fallback filtering, and runs
// wrappers at fuller strength (UnsafeArgs). Defaults, warnings, and
// the hard exclusions (no brute-force, no exploit frameworks, no DoS,
// no destruction) are unchanged.
var UnsafeEnabled bool

// autoInstallTimeout bounds one mid-scan installation.
const autoInstallTimeout = 5 * time.Minute

// defaultPublicResolvers backs ANPU_RESOLVERS when unset (keyless
// public DNS; written to a temp file per run, never a credential).
var defaultPublicResolvers = []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}

// ToolSpec describes how to run one external binary. Zero values are
// safe: no timeout override, no stdin, no prerequisites.
type ToolSpec struct {
	Name              string   // registry name (binary identity)
	Label             string   // pipeline/search label
	Toggle            string   // module toggle (defaults to Name)
	Binary            string   // executable name
	Args              []string // templates: {target} {host} {paramurl} {wordlist} {resolvers} {targetsfile} {urlsfile} {tmpdir} {codedir} {apk} {term}
	Stdin             string   // StdinHost / StdinTarget / StdinURLs / ""
	TimeoutSec        int      // 0 = defaultTimeout
	JSON              bool     // attempt structured JSON parse first
	MineHosts         bool     // mine base-domain hostnames as subdomains
	VerifyDNS         bool     // resolve mined hosts (cap 20); only confirmed kept
	RequiresWordlist  bool     // ANPU_WORDLIST or DefaultWordlist
	DefaultWordlist   string   // bundled fallback, e.g. wordlists/dirs-40.txt
	RequiresResolvers bool     // ANPU_RESOLVERS file
	RequiresCodeDir   bool     // ANPU_CODE_DIR directory (local code scope)
	RequiresAPK       bool     // ANPU_APK file (mobile scope)
	PerTech           bool     // run once per Technology with {term}
	TargetsFile       bool     // write {targetsfile} (subdomains or host)
	UrlsFile          bool     // write {urlsfile} (target + discovered endpoint URLs)
	RequiresParams    bool     // skip quietly when no parameterized URL was discovered
	ParamURL          bool     // require {paramurl} (first parameterized endpoint)
	TmpDir            bool     // provide {tmpdir} (removed after run)
	Adversarial       bool     // needs Modules.Adversarial
	UnsafeArgs        []string // full arg replacement when UnsafeEnabled (e.g. fuller strength, still no DoS)
	NoStage           bool     // install-only: no pipeline stage
	Level             string   // safe / advanced / ultra (mirrors registry)
}

// ToggleName returns the effective module toggle.
func (s *ToolSpec) ToggleName() string {
	if s.Toggle != "" {
		return s.Toggle
	}
	return s.Name
}

// LabelName returns the effective stage label.
func (s *ToolSpec) LabelName() string {
	if s.Label != "" {
		return s.Label
	}
	return titleCase(s.Name)
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// GenericScanner runs one ToolSpec as a scanner.Scanner stage.
// Resolution order: real binary → auto-install (if enabled) →
// embedded native fallbacks (zero installs, zero extra effort).
type GenericScanner struct {
	Spec *ToolSpec
	// BinaryPath overrides resolution (tests).
	BinaryPath string
	// Fallbacks are native scanners covering this tool's ground when
	// the binary is absent. Set by the pipeline; empty means no
	// embedded coverage (guidance warning instead).
	Fallbacks []scanner.Scanner
	// lastDur is the most recent execute() wall time, consumed by
	// normalize() for the verbose yield-vs-time receipt.
	lastDur time.Duration
}

// NewGeneric builds a scanner for spec.
func NewGeneric(spec *ToolSpec) *GenericScanner { return &GenericScanner{Spec: spec} }

// Name implements scanner.Scanner.
func (g *GenericScanner) Name() string { return g.Spec.Name }

func (g *GenericScanner) bin() string {
	if g.BinaryPath != "" {
		return g.BinaryPath
	}
	if path, err := findExecutable(g.Spec.Binary); err == nil {
		return path
	}
	return g.Spec.Binary
}

// Available implements scanner.Scanner: true when the binary resolves,
// when auto-install may provision it, or when embedded fallbacks exist
// (the stage always does real work — never a placeholder skip).
// Version flags are NOT required (many tools lack one).
func (g *GenericScanner) Available(_ context.Context) bool {
	if g.BinaryPath != "" {
		return true
	}
	if _, err := findExecutable(g.Spec.Binary); err == nil {
		return true
	}
	if AutoInstallEnabled {
		return true
	}
	return len(g.Fallbacks) > 0
}

// Run implements scanner.Scanner.
func (g *GenericScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	spec := g.Spec
	if spec.Adversarial && !sc.Config.Modules.Adversarial {
		return scanner.StageResult{Warnings: []string{
			fmt.Sprintf("%s skipped: state-touching tool, requires --adversarial --confirm-authorized", spec.Name)}}, nil
	}
	// Runtime gates (stack / yield / corpus) skip quietly with a
	// reason instead of burning time or printing empty-output noise.
	if skipped, ok := gatedSkip(spec, sc); ok {
		return skipped, nil
	}
	// Specs without an automated invocation (manual-recipe tools) run
	// embedded-only: ANPU never guesses CLI flags.
	if len(spec.Args) == 0 && spec.Stdin == StdinNone {
		return g.runEmbedded(ctx, sc, "")
	}
	bin := g.bin()
	if _, err := findExecutable(spec.Binary); err != nil && g.BinaryPath == "" {
		// Binary missing: self-provision under --auto-install, else
		// run embedded native fallbacks (zero installs needed).
		if AutoInstallEnabled {
			r, found := Get(spec.Name)
			if !found {
				return scanner.StageResult{Warnings: []string{
					fmt.Sprintf("%s skipped: no install recipe (and no binary)", spec.Name)}}, nil
			}
			if _, err := Install(ctx, r, autoInstallTimeout); err == nil {
				bin = g.bin()
			} else {
				return g.runEmbedded(ctx, sc, fmt.Sprintf("auto-install failed (%s), embedded coverage instead", trimMiddle(err.Error(), 120)))
			}
		}
		if _, err := findExecutable(spec.Binary); err != nil && g.BinaryPath == "" {
			return g.runEmbedded(ctx, sc, "")
		}
	}
	if spec.PerTech {
		return g.runPerTech(ctx, sc, bin)
	}
	// No parameter corpus means point-tools have nothing to test:
	// quiet skip (same reason execute() would warn with).
	if spec.ParamURL && firstParamURL(sc) == "" {
		return scanner.StageResult{Skipped: "no parameterized endpoint discovered to test"}, nil
	}
	out, repro, skipped := g.execute(ctx, sc, bin, spec.Args, nil)
	if skipped != "" {
		return scanner.StageResult{Warnings: []string{skipped}}, nil
	}
	return g.normalize(ctx, sc, out, repro, g.lastDur), nil
}

// tagScope marks every finding from a local-material stage (code
// checkout, APK) as out of target scope so the pipeline partitions it
// into the unscored appendix instead of the target finding set.
func tagScope(spec *ToolSpec, fs []models.Finding) []models.Finding {
	if !spec.RequiresCodeDir && !spec.RequiresAPK {
		return fs
	}
	for i := range fs {
		fs[i].Scope = models.ScopeLocalCode
	}
	return fs
}

// runEmbedded executes the native fallback scanners and merges their
// output plus one summary finding naming the embedded coverage (and
// the full-power install for depth). note carries context such as a
// failed auto-install.
func (g *GenericScanner) runEmbedded(ctx context.Context, sc *scanner.ScanContext, note string) (scanner.StageResult, error) {
	spec := g.Spec
	if len(g.Fallbacks) == 0 {
		_, lookErr := findExecutable(spec.Binary)
		installed := lookErr == nil || g.BinaryPath != ""
		msg := fmt.Sprintf("%s: no binary and no embedded coverage (%s)", spec.Name, installPointer(spec))
		if installed {
			msg = fmt.Sprintf("%s installed but has no safe automated invocation (%s); embedded natives cover it instead", spec.Name, installPointer(spec))
		}
		if note != "" {
			msg += "; " + note
		}
		return scanner.StageResult{Warnings: []string{msg}}, nil
	}
	var combined scanner.StageResult
	var names []string
	for _, fb := range g.Fallbacks {
		if fb == nil {
			continue
		}
		res, err := fb.Run(ctx, sc)
		if err != nil {
			combined.Warnings = append(combined.Warnings, fmt.Sprintf("%s (embedded): %v", spec.Name, err))
			continue
		}
		combined.Findings = append(combined.Findings, res.Findings...)
		combined.Technologies = append(combined.Technologies, res.Technologies...)
		combined.Endpoints = append(combined.Endpoints, res.Endpoints...)
		combined.Subdomains = append(combined.Subdomains, res.Subdomains...)
		combined.Warnings = append(combined.Warnings, res.Warnings...)
	}
	for _, fb := range g.Fallbacks {
		if fb != nil {
			names = append(names, fb.Name())
		}
	}
	summary := fmt.Sprintf("%s ran embedded (%s): %d finding(s), %d endpoint(s), %d host(s)",
		spec.Name, strings.Join(names, "+"), len(combined.Findings), len(combined.Endpoints), len(combined.Subdomains))
	if note != "" {
		summary += "; " + note
	}
	// Run receipts are verbose-only: they prove coverage for --verbose
	// runs without inflating default finding counts and reports.
	if sc.Config.Verbose {
		combined.Findings = append(combined.Findings, models.Finding{
			ID: spec.Name + "-embedded", Title: spec.LabelName() + " embedded coverage",
			Description: fmt.Sprintf("%s. For the full tool depth: %s.", summary, installPointer(spec)),
			Severity:    models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
			Target:   sc.Target.Raw,
			Evidence: models.Evidence{Observed: summary, Location: "embedded " + strings.Join(names, "+")},
			Source:   models.SourceCustom, DetectionMethod: "embedded: " + strings.Join(names, "+"),
		})
	}
	return combined, nil
}

func installPointer(spec *ToolSpec) string {
	return "anpu tools install " + spec.Name
}

// runPerTech runs the tool once per fingerprinted technology (cap 5),
// e.g. searchsploit name+version lookups. Mapping only, never exploits.
func (g *GenericScanner) runPerTech(ctx context.Context, sc *scanner.ScanContext, bin string) (scanner.StageResult, error) {
	var combined scanner.StageResult
	techs := sc.Technologies
	if len(techs) > 5 {
		techs = techs[:5]
	}
	if len(techs) == 0 {
		return scanner.StageResult{Warnings: []string{
			fmt.Sprintf("%s skipped: no fingerprinted technologies to map", g.Spec.Name)}}, nil
	}
	for _, t := range techs {
		term := strings.TrimSpace(t.Name + " " + t.Version)
		out, repro, skipped := g.execute(ctx, sc, bin, g.Spec.Args, map[string]string{"{term}": term})
		if skipped != "" {
			combined.Warnings = append(combined.Warnings, skipped)
			continue
		}
		res := g.normalize(ctx, sc, out, repro, g.lastDur)
		combined.Findings = append(combined.Findings, res.Findings...)
		combined.Endpoints = append(combined.Endpoints, res.Endpoints...)
		combined.Subdomains = append(combined.Subdomains, res.Subdomains...)
		combined.Warnings = append(combined.Warnings, res.Warnings...)
		if len(combined.Findings) >= maxToolFinds {
			break
		}
	}
	return combined, nil
}

// execute resolves templates, checks prerequisites, runs the binary,
// and returns raw stdout. A non-empty skipped string means warn-and-skip.
func (g *GenericScanner) execute(ctx context.Context, sc *scanner.ScanContext, bin string, args []string, extra map[string]string) (out []byte, repro, skipped string) {
	spec := g.Spec
	repl := map[string]string{
		"{target}": sc.Target.Raw,
		"{host}":   sc.Target.Host,
	}
	for k, v := range extra {
		repl[k] = v
	}
	var tmpCleanup []func()
	defer func() {
		for _, fn := range tmpCleanup {
			fn()
		}
	}()
	if spec.ParamURL {
		pu := firstParamURL(sc)
		if pu == "" {
			return nil, "", fmt.Sprintf("%s skipped: no parameterized endpoint discovered to test", spec.Name)
		}
		repl["{paramurl}"] = pu
	}
	if spec.RequiresWordlist {
		wl := strings.TrimSpace(os.Getenv("ANPU_WORDLIST"))
		if wl == "" && spec.DefaultWordlist != "" {
			if _, err := os.Stat(spec.DefaultWordlist); err == nil {
				wl = spec.DefaultWordlist
			}
		}
		if wl == "" {
			return nil, "", fmt.Sprintf("%s skipped: set ANPU_WORDLIST=/path/to/wordlist.txt (bounded fuzzing needs an explicit list)", spec.Name)
		}
		repl["{wordlist}"] = wl
	}
	if spec.RequiresResolvers {
		rs := strings.TrimSpace(os.Getenv("ANPU_RESOLVERS"))
		if rs == "" {
			// Zero-effort default: public resolvers in a temp file.
			var err error
			rs, err = defaultResolversFile()
			if err != nil {
				return nil, "", fmt.Sprintf("%s skipped: set ANPU_RESOLVERS=/path/to/resolvers.txt", spec.Name)
			}
			tmpCleanup = append(tmpCleanup, func() { os.Remove(rs) })
		}
		repl["{resolvers}"] = rs
	}
	if spec.RequiresCodeDir {
		cd := strings.TrimSpace(os.Getenv("ANPU_CODE_DIR"))
		if info, err := os.Stat(cd); err != nil || !info.IsDir() {
			return nil, "", fmt.Sprintf("%s skipped: set ANPU_CODE_DIR=/path/to/local/code (local code scope only)", spec.Name)
		}
		repl["{codedir}"] = cd
	}
	if spec.RequiresAPK {
		apk := strings.TrimSpace(os.Getenv("ANPU_APK"))
		if info, err := os.Stat(apk); err != nil || info.IsDir() {
			return nil, "", fmt.Sprintf("%s skipped: set ANPU_APK=/path/to/app.apk (mobile scope; static first, dynamic never auto-run)", spec.Name)
		}
		repl["{apk}"] = apk
	}
	if spec.TargetsFile {
		lines := sc.Subdomains
		if len(lines) == 0 {
			lines = []string{sc.Target.Host}
		}
		f, err := os.CreateTemp("", "anpu-targets-*.txt")
		if err != nil {
			return nil, "", fmt.Sprintf("%s: temp targets file: %v", spec.Name, err)
		}
		tmpCleanup = append(tmpCleanup, func() { os.Remove(f.Name()) })
		for _, l := range lines {
			fmt.Fprintln(f, l)
		}
		f.Close()
		repl["{targetsfile}"] = f.Name()
	}
	if spec.UrlsFile {
		f, err := os.CreateTemp("", "anpu-urls-*.txt")
		if err != nil {
			return nil, "", fmt.Sprintf("%s: temp urls file: %v", spec.Name, err)
		}
		tmpCleanup = append(tmpCleanup, func() { os.Remove(f.Name()) })
		for _, l := range urlList(sc) {
			fmt.Fprintln(f, l)
		}
		f.Close()
		repl["{urlsfile}"] = f.Name()
	}
	if spec.TmpDir {
		dir, err := os.MkdirTemp("", "anpu-tool-*")
		if err != nil {
			return nil, "", fmt.Sprintf("%s: temp dir: %v", spec.Name, err)
		}
		tmpCleanup = append(tmpCleanup, func() { os.RemoveAll(dir) })
		repl["{tmpdir}"] = dir
	}
	// Unsafe mode runs the fuller-strength arg set where defined
	// (still no DoS, no destruction — see UnsafeEnabled contract).
	useArgs := args
	if UnsafeEnabled && len(spec.UnsafeArgs) > 0 {
		useArgs = spec.UnsafeArgs
	}
	expanded := make([]string, 0, len(useArgs))
	for _, a := range useArgs {
		for k, v := range repl {
			a = strings.ReplaceAll(a, k, v)
		}
		expanded = append(expanded, a)
	}
	repro = bin + " " + strings.Join(expanded, " ")
	timeout := spec.TimeoutSec
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, bin, expanded...)
	switch spec.Stdin {
	case StdinHost:
		cmd.Stdin = strings.NewReader(sc.Target.Host + "\n")
	case StdinTarget:
		cmd.Stdin = strings.NewReader(sc.Target.Raw + "\n")
	case StdinURLs:
		cmd.Stdin = strings.NewReader(strings.Join(urlList(sc), "\n") + "\n")
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	t0 := time.Now()
	runErr := cmd.Run() // exit codes are informational; output is what matters
	g.lastDur = time.Since(t0)
	out = stdout.Bytes()
	if len(out) > maxToolOutput {
		out = out[:maxToolOutput]
	}
	if len(bytes.TrimSpace(out)) == 0 {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" && runErr != nil {
			detail = runErr.Error()
		}
		if runCtx.Err() == context.DeadlineExceeded {
			return nil, repro, fmt.Sprintf("%s timed out after %ds with no output", spec.Name, timeout)
		}
		if detail == "" {
			return nil, repro, fmt.Sprintf("%s: completed with no findings on this target", spec.Name)
		}
		return nil, repro, fmt.Sprintf("%s produced no output (%s)", spec.Name, trimMiddle(detail, 300))
	}
	return out, repro, ""
}

// normalize converts raw tool output into ANPU artifacts. dur is the
// binary's own wall time: the verbose run receipt logs it next to the
// mined yield (endpoints/hosts/output bytes), so slow tools with thin
// yield (e.g. amass burning its full timeout for ~0 hosts) are visible
// in verbose runs without any new channel.
func (g *GenericScanner) normalize(ctx context.Context, sc *scanner.ScanContext, out []byte, repro string, dur time.Duration) scanner.StageResult {
	spec := g.Spec
	var res scanner.StageResult
	if spec.JSON {
		if fr := parseJSONFindings(spec, sc, out, repro); len(fr) > 0 {
			res.Findings = append(res.Findings, fr...)
		}
	}
	if fr, techs := parseSpecial(spec, sc, out, repro); len(fr) > 0 || len(techs) > 0 {
		res.Findings = append(res.Findings, fr...)
		res.Technologies = append(res.Technologies, techs...)
	}
	for _, u := range mineURLs(out, sc) {
		res.Endpoints = append(res.Endpoints, models.Endpoint{URL: u, Category: models.EndpointUnknown, Sources: []string{spec.Name}})
	}
	hosts := mineHosts(out, sc)
	if spec.VerifyDNS {
		hosts = verifyHosts(ctx, hosts)
	}
	res.Subdomains = append(res.Subdomains, hosts...)
	summary := fmt.Sprintf("%s: %d endpoint(s), %d host(s) from %d output bytes in %.1fs", spec.Name, len(res.Endpoints), len(res.Subdomains), len(out), dur.Seconds())
	// Run receipts are verbose-only (see runEmbedded).
	if sc.Config.Verbose {
		res.Findings = append(res.Findings, models.Finding{
			ID: spec.Name + "-run", Title: spec.LabelName() + " external run",
			Description: fmt.Sprintf("External tool %s executed and normalized (%s). Install: anpu tools install %s. Absence warn-and-skips; this finding proves the run happened.", spec.Name, summary, spec.Name),
			Severity:    models.SeverityInfo, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
			Target:   sc.Target.Raw,
			Evidence: models.Evidence{Observed: summary + " — " + trimMiddle(firstLines(out, 3), 300), Location: "external " + spec.Binary + " output"},
			Source:   models.SourceCustom, DetectionMethod: "external: " + trimMiddle(repro, 300),
		})
	}
	if len(res.Findings) > maxToolFinds+1 {
		res.Findings = res.Findings[:maxToolFinds+1]
	}
	// Code/APK stages analyze operator-supplied local material, not
	// the target: tag out of target scope (unscored appendix).
	res.Findings = tagScope(spec, res.Findings)
	return res
}

// defaultResolversFile writes the public-resolver fallback list.
func defaultResolversFile() (string, error) {
	f, err := os.CreateTemp("", "anpu-resolvers-*.txt")
	if err != nil {
		return "", err
	}
	for _, r := range defaultPublicResolvers {
		fmt.Fprintln(f, r)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func firstParamURL(sc *scanner.ScanContext) string {
	for _, ep := range sc.Endpoints {
		if strings.Contains(ep.URL, "?") {
			return ep.URL
		}
	}
	return ""
}

func urlList(sc *scanner.ScanContext) []string {
	out := []string{sc.Target.Raw}
	var rest []string
	for _, ep := range sc.Endpoints {
		if len(out)+len(rest) >= 9 {
			break
		}
		if !strings.HasPrefix(ep.URL, "http") {
			continue
		}
		// Parameterized URLs first: stdin consumers (kxss, gxss, arjun,
		// unfurl keys) are only useful with query strings present.
		if strings.Contains(ep.URL, "?") {
			out = append(out, ep.URL)
		} else {
			rest = append(rest, ep.URL)
		}
	}
	out = append(out, rest...)
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

var urlMineRe = regexp.MustCompile(`https?://[^\s"'<>\]\)]+`)

func mineURLs(out []byte, sc *scanner.ScanContext) []string {
	seen := map[string]bool{}
	var urls []string
	base := registrableBase(sc.Target.Host)
	for _, m := range urlMineRe.FindAllString(string(out), -1) {
		m = strings.TrimRight(m, ".,;:'\"!?)]}\\")
		if seen[m] || len(urls) >= maxMinedURLs {
			continue
		}
		host := hostOf(m)
		if host == "" {
			continue
		}
		lh := strings.ToLower(host)
		if !strings.EqualFold(lh, sc.Target.Host) && !strings.HasSuffix(lh, "."+base) {
			continue // keep the stage scoped to the target's base domain
		}
		seen[m] = true
		urls = append(urls, m)
	}
	sort.Strings(urls)
	return urls
}

var hostMineRe = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b`)

func mineHosts(out []byte, sc *scanner.ScanContext) []string {
	base := registrableBase(sc.Target.Host)
	seen := map[string]bool{}
	var hosts []string
	for _, m := range hostMineRe.FindAllString(string(out), -1) {
		h := strings.ToLower(strings.TrimSuffix(m, "."))
		if seen[h] || len(hosts) >= maxMinedHosts {
			continue
		}
		if !strings.EqualFold(h, sc.Target.Host) && !strings.HasSuffix(h, "."+base) {
			continue
		}
		if strings.HasSuffix(h, ".png") || strings.HasSuffix(h, ".jpg") || strings.HasSuffix(h, ".css") || strings.HasSuffix(h, ".js") {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

func verifyHosts(ctx context.Context, hosts []string) []string {
	var out []string
	for i, h := range hosts {
		if i >= maxVerifyDNS {
			break
		}
		rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ips, err := net.DefaultResolver.LookupIPAddr(rctx, h)
		cancel()
		if err == nil && len(ips) > 0 {
			out = append(out, h)
		}
	}
	return out
}

func registrableBase(host string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func hostOf(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	h := raw[i+3:]
	for _, sep := range []string{"/", "?", "#", ":"} {
		if j := strings.Index(h, sep); j >= 0 {
			h = h[:j]
		}
	}
	return h
}

func firstLines(out []byte, n int) string {
	lines := strings.Split(string(out), "\n")
	var kept []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			kept = append(kept, strings.TrimSpace(l))
		}
		if len(kept) >= n {
			break
		}
	}
	return strings.Join(kept, " | ")
}

func trimMiddle(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// mapSeverity normalizes tool severity strings.
func mapSeverity(s string) models.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit", "5", "error":
		return models.SeverityCritical
	case "high", "3", "important", "warning":
		// note: semgrep WARNING → Medium handled by caller override
		return models.SeverityHigh
	case "medium", "moderate", "med", "2":
		return models.SeverityMedium
	case "low", "1", "note", "info", "informational", "unknown":
		return models.SeverityLow
	}
	return models.SeverityInfo
}
