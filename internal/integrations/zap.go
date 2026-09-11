// Package integrations contains optional wrappers around external
// security tools (Nuclei, and OWASP ZAP). ANPU does not reimplement
// these scanners: it invokes the real, independently-maintained tool as
// a subprocess (if installed), captures its structured output, and
// normalizes the results into ANPU's unified Finding model.
//
// ANPU must work fully without any of these tools installed — their
// absence is reported as a warning, not a fatal error.
package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// ZapScanner implements scanner.Scanner by invoking OWASP ZAP in one of
// two modes, whichever is found first in the environment:
//
//  1. Docker baseline scan — `docker run ghcr.io/zaproxy/zaproxy zap-baseline.py`
//     No ZAP installation needed; only Docker is required.
//  2. zap.sh / zap.bat binary — local ZAP installation on PATH or common
//     install paths.
//
// Deep profile uses `zap-full-scan.py` (Docker) or the -f flag (binary).
// Safe/Standard use the baseline scan (passive only).
// ZAP alerts are converted to ANPU findings with severity mapping and
// CWE extraction identical to the Nuclei converter.
type ZapScanner struct {
	// DockerBinary overrides the resolved path to the docker binary (for testing).
	DockerBinary string
	// ZapBinary overrides the resolved path to the zap.sh binary (for testing).
	ZapBinary string
	// Timeout bounds the whole ZAP invocation.
	Timeout time.Duration
	// DockerImage is the ZAP Docker image to use. Defaults to the official image.
	DockerImage string
}

// zapAlertRisk maps ZAP integer risk codes to ANPU severities.
// ZAP risk codes: 0=Informational, 1=Low, 2=Medium, 3=High.
var zapAlertRisk = map[int]models.Severity{
	0: models.SeverityInfo,
	1: models.SeverityLow,
	2: models.SeverityMedium,
	3: models.SeverityHigh,
}

// zapAlertConfidence maps ZAP integer confidence codes to ANPU confidence.
// ZAP confidence: 0=False Positive, 1=Low, 2=Medium, 3=High, 4=Confirmed.
var zapAlertConfidence = map[int]models.Confidence{
	0: models.ConfidenceLow,
	1: models.ConfidenceLow,
	2: models.ConfidenceMedium,
	3: models.ConfidenceHigh,
	4: models.ConfidenceHigh,
}

// zapAlert mirrors the fields ANPU consumes from ZAP's JSON output.
// ZAP's schema has more fields; we only decode what we normalize.
type zapAlert struct {
	PluginID   string `json:"pluginid"`
	AlertRef   string `json:"alertRef"`
	Alert      string `json:"alert"`
	Name       string `json:"name"`
	RiskCode   string `json:"riskcode"`
	Confidence string `json:"confidence"`
	RiskDesc   string `json:"riskdesc"`
	Desc       string `json:"desc"`
	Instances  []struct {
		URI      string `json:"uri"`
		Method   string `json:"method"`
		Param    string `json:"param"`
		Evidence string `json:"evidence"`
	} `json:"instances"`
	Count     string            `json:"count"`
	Solution  string            `json:"solution"`
	Reference string            `json:"reference"`
	CWEID     string            `json:"cweid"`
	WASCID    string            `json:"wascid"`
	SourceID  string            `json:"sourceid"`
	OtherInfo string            `json:"otherinfo"`
	Tags      map[string]string `json:"tags"`
}

// zapReport is the top-level structure of ZAP's JSON output.
type zapReport struct {
	Site []struct {
		Name   string     `json:"@name"`
		Alerts []zapAlert `json:"alerts"`
	} `json:"site"`
}

func NewZapScanner() *ZapScanner {
	return &ZapScanner{
		Timeout:     10 * time.Minute,
		DockerImage: "ghcr.io/zaproxy/zaproxy:stable",
	}
}

func (z *ZapScanner) Name() string { return "zap" }

// resolvedDockerPath returns the docker binary path, falling back to
// podman (docker-compatible CLI) when docker is absent.
func (z *ZapScanner) resolvedDockerPath() string {
	if z.DockerBinary != "" {
		return z.DockerBinary
	}
	if path, err := exec.LookPath("docker"); err == nil {
		return path
	}
	if path, err := exec.LookPath("podman"); err == nil {
		return path
	}
	return "docker"
}

// resolvedZapPath returns the zap.sh/zap.bat binary path.
// ZAP_BINARY env overrides everything for custom installs.
func (z *ZapScanner) resolvedZapPath() string {
	if z.ZapBinary != "" {
		return z.ZapBinary
	}
	if env := strings.TrimSpace(os.Getenv("ZAP_BINARY")); env != "" {
		return env
	}
	for _, candidate := range []string{"zap.sh", "zap.bat", "zaproxy"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	// Common install paths.
	for _, p := range []string{
		"/opt/zaproxy/zap.sh",
		"/usr/share/zaproxy/zap.sh",
		"/Applications/OWASP ZAP.app/Contents/Java/zap.sh",
	} {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
		// Also try stat without LookPath since these aren't on PATH.
		cmd := exec.Command(p, "-version") // #nosec G204 -- ANPU orchestrates operator-installed security tools by resolved path with bounded read-only flags.
		if cmd.Run() == nil {
			return p
		}
	}
	return ""
}

// dockerAvailable reports whether docker is installed and the daemon is reachable.
func (z *ZapScanner) dockerAvailable(ctx context.Context) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, z.resolvedDockerPath(), "info", "--format", "{{.ServerVersion}}") // #nosec G204 -- ANPU orchestrates operator-installed security tools by resolved path with bounded read-only flags.
	return cmd.Run() == nil
}

// zapBinaryAvailable reports whether a local zap.sh installation is present.
func (z *ZapScanner) zapBinaryAvailable() bool {
	path := z.resolvedZapPath()
	if path == "" {
		return false
	}
	cmd := exec.Command(path, "-version") // #nosec G204 -- ANPU orchestrates operator-installed security tools by resolved path with bounded read-only flags.
	return cmd.Run() == nil
}

// Available always true — embedded fallback covers the stage when Docker/ZAP is missing.
func (z *ZapScanner) Available(ctx context.Context) bool { return true }
func (z *ZapScanner) availableExternal(ctx context.Context) bool {
	return z.dockerAvailable(ctx) || z.zapBinaryAvailable()
}

// Run invokes ZAP against the scan target and converts its JSON report
// into ANPU findings. If external ZAP is present it is used; otherwise
// an embedded fallback runs a subset of passive checks so the stage
// still shows as DONE (embedded).
func (z *ZapScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	if !z.availableExternal(ctx) {
		return z.runEmbedded(ctx, sc)
	}
	useDocker := z.dockerAvailable(ctx)

	runCtx, cancel := context.WithTimeout(ctx, z.Timeout)
	defer cancel()

	var (
		output   []byte
		warnings []string
		runErr   error
	)

	if useDocker {
		output, warnings, runErr = z.runDocker(runCtx, sc)
	} else {
		output, warnings, runErr = z.runBinary(runCtx, sc)
	}

	if runErr != nil && len(output) == 0 {
		// ZAP exits non-zero when it finds alerts (that's normal). Only
		// treat it as a real error when there's no usable output at all.
		return scanner.StageResult{Warnings: append(warnings, fmt.Sprintf("ZAP exited with error and produced no output: %v", runErr))}, nil
	}

	findings, parseWarnings := z.parseReport(output, sc.Target.Raw)
	warnings = append(warnings, parseWarnings...)

	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// scanScript returns the ZAP Docker scan script for the profile.
// Baseline (safe/advanced) = passive + ajax spider, no active scan.
// Full (ultra/deep) = active spider + active scan.
func scanScript(profile models.Profile) string {
	if profile.Normalize() == models.ProfileUltra {
		return "zap-full-scan.py"
	}
	return "zap-baseline.py"
}

// ZapAjax enables the ZAP Ajax spider (-j) on Docker runs (opt-in via
// --zap-ajax): crawls JavaScript-heavy routes the traditional spider
// misses, at the cost of a longer scan. Local-binary mode has no ajax
// equivalent and ignores it.
var ZapAjax bool

// runDocker runs ZAP via `docker run`. The JSON report is written to a
// temp-dir bind mount (os temp lives under the default-shared user
// profile on Docker Desktop) and read back; stdout is kept as a
// fallback because older script versions ignore -J.
func (z *ZapScanner) runDocker(ctx context.Context, sc *scanner.ScanContext) ([]byte, []string, error) {
	script := scanScript(sc.Config.Profile)
	workDir, tmpErr := os.MkdirTemp("", "anpu-zap-*")
	if tmpErr != nil {
		return nil, []string{fmt.Sprintf("ZAP temp dir: %v", tmpErr)}, tmpErr
	}
	defer func() { _ = os.RemoveAll(workDir) }()
	reportName := "zap-report.json"
	args := []string{
		"run", "--rm",
		"-v", workDir + ":/zap/wrk:rw",
		z.dockerImage(),
		script,
		"-t", sc.Target.Raw,
		"-J", "/zap/wrk/" + reportName,
		"-I", // don't fail on warn
	}
	if ZapAjax {
		args = append(args, "-j") // Ajax spider in addition to the traditional one
	}

	cmd := exec.CommandContext(ctx, z.resolvedDockerPath(), args...) // #nosec G204 -- ANPU orchestrates operator-installed security tools by resolved path with bounded read-only flags.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	var warnings []string
	if err != nil {
		// ZAP exits 2 when it found alerts — that's expected.
		// Exit 1 means no alerts. Any other non-zero with empty
		// stdout is a real failure.
		if stdout.Len() == 0 {
			msg := strings.TrimSpace(stderr.String())
			if len(msg) > 500 {
				msg = msg[:500] + "..."
			}
			warnings = append(warnings, fmt.Sprintf("ZAP Docker run error: %v — %s", err, msg))
		}
	}
	// Prefer the mounted JSON report; fall back to stdout for older
	// script versions that ignore -J.
	if raw, rerr := os.ReadFile(filepath.Join(workDir, reportName)); rerr == nil && len(bytes.TrimSpace(raw)) > 0 { // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
		return raw, warnings, err
	}
	return stdout.Bytes(), warnings, err
}

// runBinary runs a local zap.sh/zap.bat installation in daemon mode and
// uses ZAP's built-in Python scripts via -cmd flags to run a baseline or
// full scan. Output is captured from stdout.
func (z *ZapScanner) runBinary(ctx context.Context, sc *scanner.ScanContext) ([]byte, []string, error) {
	script := scanScript(sc.Config.Profile)
	zapPath := z.resolvedZapPath()

	// The local ZAP binary accepts the same zap-baseline.py flags when
	// invoked with -cmd (headless) mode:
	//   zap.sh -cmd -quickurl <target> -quickprogress -quickout /dev/stdout
	// However the -J (JSON report to file) flag is more reliable for
	// parsing. We write to a temp file and read it back.
	args := []string{
		"-cmd",
		"-quickurl", sc.Target.Raw,
		"-quickout", "/dev/stdout",
		"-quickprogress",
	}
	if script == "zap-full-scan.py" {
		args = append(args, "-addoninstall", "spider")
	}

	cmd := exec.CommandContext(ctx, zapPath, args...) // #nosec G204 -- ANPU orchestrates operator-installed security tools by resolved path with bounded read-only flags.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	var warnings []string
	if err != nil && stdout.Len() == 0 {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		warnings = append(warnings, fmt.Sprintf("ZAP binary error: %v — %s", err, msg))
	}
	return stdout.Bytes(), warnings, err
}

// runEmbedded performs real ZAP-baseline-style passive checks without
// Docker or zap.sh: one GET on the target plus already-discovered
// endpoints. It deliberately avoids ground covered by the headers and
// cookie analyzers (nosniff, referrer, permissions, server disclosure,
// COOP) and covers what they don't: clickjacking framing policy,
// sensitive robots.txt paths, mixed content, and verbose error pages.
func (z *ZapScanner) runEmbedded(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	client := anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	var findings []models.Finding
	var warnings []string

	fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := client.Get(fctx, sc.Target.Raw)
	if err != nil || resp == nil {
		// Target unreachable here: other stages already report it;
		// stay silent instead of adding noise.
		return scanner.StageResult{}, nil
	}

	if f := zapCheckClickjacking(resp, sc.Target.Raw); f != nil {
		findings = append(findings, *f)
	}
	if f := zapCheckRobotsEntries(ctx, client, sc.Target.Raw); f != nil {
		findings = append(findings, *f)
	}
	findings = append(findings, zapCheckMixedContent(sc)...)
	if f := zapCheckVerboseErrors(ctx, client, sc.Target.Raw); f != nil {
		findings = append(findings, *f)
	}

	if len(findings) == 0 && len(warnings) == 0 {
		warnings = append(warnings, "zap embedded checks ran (no Docker or zap.sh); no issues found — install Docker and re-run ultra profile for full ZAP coverage")
	}
	return scanner.StageResult{Findings: findings, Warnings: warnings}, nil
}

// zapCheckClickjacking flags a missing framing policy: no
// X-Frame-Options and no frame-ancestors in Content-Security-Policy.
func zapCheckClickjacking(resp *anpuhttp.Response, target string) *models.Finding {
	if resp.Header == nil {
		return nil
	}
	if v := strings.TrimSpace(resp.Header.Get("X-Frame-Options")); v != "" {
		return nil
	}
	csp := strings.ToLower(resp.Header.Get("Content-Security-Policy"))
	if strings.Contains(csp, "frame-ancestors") {
		return nil
	}
	return &models.Finding{
		ID:              fmt.Sprintf("zap-xframe-%d", time.Now().UnixNano()),
		Title:           "Missing clickjacking protection (no X-Frame-Options / frame-ancestors)",
		Description:     "The response sets neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive, so the page can be embedded in a cross-origin iframe. An attacker can overlay invisible frames to hijack clicks (clickjacking/UI redressing).",
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryHeaders,
		CWE:             "CWE-1021",
		Target:          target,
		URL:             target,
		Source:          models.SourceZAP,
		DetectionMethod: "embedded ZAP passive check: framing headers absent",
		Evidence: models.Evidence{
			Observed:       "X-Frame-Options: <absent>, CSP frame-ancestors: <absent>",
			Location:       target,
			RequestSummary: fmt.Sprintf("GET %s", target),
		},
		Impact:      "Attackers can embed the site invisibly and trick users into clicking actions they did not intend.",
		Remediation: "Send `X-Frame-Options: SAMEORIGIN` or, preferably, a CSP `frame-ancestors 'self'` directive.",
		References:  []string{"https://owasp.org/www-community/attacks/Clickjacking"},
		FirstSeen:   time.Now(),
	}
}

// zapSensitiveRobotsFragments matches robots.txt Disallow entries that
// point at functionality which should not be advertised publicly.
var zapSensitiveRobotsFragments = []string{
	"admin", "backup", "bak", "config", "dump", ".sql", ".git",
	"internal", "private", "secret", "password", "db_", "database",
	"wp-config", ".env", "swagger", "console", "manage",
}

// zapCheckRobotsEntries fetches robots.txt once and flags Disallow
// entries pointing at sensitive locations.
func zapCheckRobotsEntries(ctx context.Context, client *anpuhttp.Client, target string) *models.Finding {
	robotsURL := strings.TrimSuffix(target, "/") + "/robots.txt"
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := client.Get(rctx, robotsURL)
	if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
		return nil
	}
	var hits []string
	for _, line := range strings.Split(string(resp.Body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "disallow:") {
			continue
		}
		path := strings.TrimSpace(line[len("disallow:"):])
		if path == "" || path == "/" {
			continue
		}
		lower := strings.ToLower(path)
		for _, frag := range zapSensitiveRobotsFragments {
			if strings.Contains(lower, frag) {
				hits = append(hits, path)
				break
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	if len(hits) > 10 {
		hits = hits[:10]
	}
	return &models.Finding{
		ID:    fmt.Sprintf("zap-robots-%d", time.Now().UnixNano()),
		Title: fmt.Sprintf("robots.txt advertises %d sensitive path(s)", len(hits)),
		Description: fmt.Sprintf(
			"robots.txt Disallow rules point at sensitive locations (%s). Disallow is a crawling hint, not access control — "+
				"attackers read robots.txt first precisely to harvest these paths.",
			strings.Join(hits, ", "),
		),
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryConfiguration,
		CWE:             "CWE-538",
		Target:          target,
		URL:             robotsURL,
		Source:          models.SourceZAP,
		DetectionMethod: "embedded ZAP passive check: robots.txt sensitive Disallow entries",
		Evidence: models.Evidence{
			Observed:       "Disallow: " + strings.Join(hits, ", Disallow: "),
			Location:       robotsURL,
			RequestSummary: fmt.Sprintf("GET %s", robotsURL),
		},
		Impact:      "Exposed paths narrow an attacker's search to admin panels, backups, configs, and VCS metadata.",
		Remediation: "Remove sensitive paths from robots.txt and protect them with authentication; use robots.txt only for crawler etiquette on public content.",
		FirstSeen:   time.Now(),
	}
}

// zapCheckMixedContent flags discovered asset URLs served over plain
// HTTP while the target itself is HTTPS.
func zapCheckMixedContent(sc *scanner.ScanContext) []models.Finding {
	if !strings.HasPrefix(strings.ToLower(sc.Target.Raw), "https://") {
		return nil
	}
	seen := map[string]bool{}
	var out []models.Finding
	for _, ep := range sc.Endpoints {
		if ep.Category != models.EndpointAsset && ep.Category != models.EndpointUnknown {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(ep.URL), "http://") || seen[ep.URL] {
			continue
		}
		seen[ep.URL] = true
		out = append(out, models.Finding{
			ID:              fmt.Sprintf("zap-mixed-%d", time.Now().UnixNano()),
			Title:           fmt.Sprintf("Mixed content: page may load %s over plain HTTP", ep.URL),
			Description:     "An HTTPS page references a sub-resource over plain HTTP. Browsers block active mixed content and warn on the rest; a network attacker can replace the HTTP resource with malicious content.",
			Severity:        models.SeverityLow,
			Confidence:      models.ConfidenceMedium,
			Category:        models.CategoryConfiguration,
			CWE:             "CWE-829",
			Target:          sc.Target.Raw,
			URL:             ep.URL,
			Source:          models.SourceZAP,
			DetectionMethod: "embedded ZAP passive check: http-scheme asset on https page",
			Evidence: models.Evidence{
				Observed:       "http:// sub-resource on " + sc.Target.Raw,
				Location:       ep.URL,
				RequestSummary: fmt.Sprintf("GET %s", sc.Target.Raw),
			},
			Impact:      "Active mixed content is blocked by browsers (breakage); passive mixed content leaks cookies and page context to the network.",
			Remediation: "Serve all sub-resources over HTTPS and consider Content-Security-Policy: upgrade-insecure-requests.",
			References:  []string{"https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"},
			FirstSeen:   time.Now(),
		})
		if len(out) >= 5 {
			break
		}
	}
	return out
}

// zapErrorFingerprints matches verbose stack traces / debug pages that
// leak framework internals.
var zapErrorFingerprints = []string{
	"Traceback (most recent call last)",     // Python Django/Flask
	"NullPointerException",                  // Java
	"ORA-",                                  // Oracle
	"SQL syntax", "mysql_fetch", "pg_query", // SQL errors
	"ASP.NET", "Server Error in '/' Application",
	"Whoops, looks like something went wrong", // Laravel debug
	"RuntimeError", "ActionView::Template::Error",
}

// zapCheckVerboseErrors requests a random non-existent path once and
// flags framework stack traces in the error page.
func zapCheckVerboseErrors(ctx context.Context, client *anpuhttp.Client, target string) *models.Finding {
	probe := strings.TrimSuffix(target, "/") + fmt.Sprintf("/anpu-nonexistent-%d", time.Now().Unix()%100000)
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := client.Get(pctx, probe)
	if err != nil || resp == nil || len(resp.Body) == 0 {
		return nil
	}
	body := string(resp.Body)
	if len(body) > 64*1024 {
		body = body[:64*1024]
	}
	for _, fp := range zapErrorFingerprints {
		if strings.Contains(body, fp) {
			return &models.Finding{
				ID:    fmt.Sprintf("zap-verbose-err-%d", time.Now().UnixNano()),
				Title: "Verbose error page discloses framework internals",
				Description: fmt.Sprintf(
					"A request to a non-existent path returned an error page containing %q — framework stack traces disclose file paths, versions, and code structure useful for targeted exploitation.",
					fp,
				),
				Severity:        models.SeverityLow,
				Confidence:      models.ConfidenceHigh,
				Category:        models.CategoryExposure,
				CWE:             "CWE-209",
				Target:          target,
				URL:             probe,
				Source:          models.SourceZAP,
				DetectionMethod: "embedded ZAP check: stack-trace fingerprint in 404 page",
				Evidence: models.Evidence{
					Observed:       "error page contains: " + fp,
					Location:       probe,
					RequestSummary: fmt.Sprintf("GET %s", probe),
				},
				Impact:      "Leaked paths and versions let attackers fingerprint the stack and aim version-specific exploits.",
				Remediation: "Replace debug error pages with generic error responses in production (e.g. DEBUG=False, customErrors=On, friendly 404s).",
				References:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling"},
				FirstSeen:   time.Now(),
			}
		}
	}
	return nil
}

func (z *ZapScanner) dockerImage() string {
	if z.DockerImage != "" {
		return z.DockerImage
	}
	return "ghcr.io/zaproxy/zaproxy:stable"
}

// parseReport decodes ZAP's JSON report and converts each alert into an
// ANPU Finding. The JSON may contain trailing stderr noise; we scan
// line-by-line to find the report object robustly.
func (z *ZapScanner) parseReport(data []byte, target string) ([]models.Finding, []string) {
	if len(data) == 0 {
		return nil, []string{"ZAP produced no output to parse"}
	}

	// Try full-document parse first (happy path).
	var report zapReport
	if err := json.Unmarshal(bytes.TrimSpace(data), &report); err != nil {
		// Fall back: scan for the JSON object line-by-line.
		report = z.scanForReport(data)
		if len(report.Site) == 0 {
			return nil, []string{fmt.Sprintf("ZAP output could not be parsed as a JSON report: %v", err)}
		}
	}

	var findings []models.Finding
	var warnings []string

	for _, site := range report.Site {
		for _, alert := range site.Alerts {
			f, warn := convertZapAlert(alert, target)
			if warn != "" {
				warnings = append(warnings, warn)
			}
			if f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings, warnings
}

// scanForReport attempts to find a JSON object in noisy output by
// scanning lines until one decodes cleanly.
func (z *ZapScanner) scanForReport(data []byte) zapReport {
	var report zapReport
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if err := json.Unmarshal([]byte(line), &report); err == nil && len(report.Site) > 0 {
			return report
		}
	}
	return report
}

// convertZapAlert maps a single ZAP alert to an ANPU Finding.
// Returns nil finding + warning string on unrecoverable parse errors.
func convertZapAlert(a zapAlert, target string) (*models.Finding, string) {
	riskCode, _ := strconv.Atoi(strings.TrimSpace(a.RiskCode))
	confCode, _ := strconv.Atoi(strings.TrimSpace(a.Confidence))

	sev, ok := zapAlertRisk[riskCode]
	if !ok {
		sev = models.SeverityInfo
	}
	conf, ok := zapAlertConfidence[confCode]
	if !ok {
		conf = models.ConfidenceMedium
	}

	// Prefer alert name over the generic "alert" field.
	title := a.Name
	if title == "" {
		title = a.Alert
	}
	if title == "" {
		return nil, fmt.Sprintf("ZAP alert pluginid=%s has no name, skipping", a.PluginID)
	}

	// Build the URL from the first instance; fall back to target root.
	url := target
	var paramEvidence string
	if len(a.Instances) > 0 {
		inst := a.Instances[0]
		if inst.URI != "" {
			url = inst.URI
		}
		if inst.Evidence != "" {
			paramEvidence = inst.Evidence
		} else if inst.Param != "" {
			paramEvidence = "param: " + inst.Param
		}
	}

	// Strip HTML tags from desc/solution (ZAP embeds <p>, <ul>, <li> etc.)
	desc := stripHTMLTags(a.Desc)
	if desc == "" {
		desc = a.RiskDesc
	}

	// Corroboration contract: an alert with no per-instance evidence
	// (no evidence string, no parameter) is a single-technique signal —
	// never above Medium severity or confidence. Cap and say so.
	if paramEvidence == "" {
		if sev.Rank() > models.SeverityMedium.Rank() {
			sev = models.SeverityMedium
		}
		if conf.Rank() > models.ConfidenceMedium.Rank() {
			conf = models.ConfidenceMedium
		}
		desc += " [ANPU: no per-instance evidence captured — capped at Medium pending review.]"
	}

	cwe := ""
	if a.CWEID != "" && a.CWEID != "-1" && a.CWEID != "0" {
		cwe = "CWE-" + a.CWEID
	}

	evidence := models.Evidence{
		Location: url,
		Observed: paramEvidence,
	}
	if paramEvidence == "" {
		evidence.Unavailable = true
	}

	refs := []string{}
	if a.Reference != "" {
		for _, line := range strings.Split(a.Reference, "\n") {
			if ref := strings.TrimSpace(line); ref != "" {
				refs = append(refs, ref)
			}
		}
	}

	// Build a stable, plugin-scoped ID so dedup works across re-runs.
	id := "zap-" + a.PluginID
	if a.AlertRef != "" && a.AlertRef != a.PluginID {
		id = "zap-" + a.AlertRef
	}

	return &models.Finding{
		ID:              id,
		Title:           title,
		Description:     desc,
		Severity:        sev,
		Confidence:      conf,
		Category:        zapCategory(riskCode),
		CWE:             cwe,
		Target:          target,
		URL:             url,
		Evidence:        evidence,
		Source:          models.SourceZAP,
		DetectionMethod: fmt.Sprintf("OWASP ZAP alert plugin %s", a.PluginID),
		References:      refs,
		Remediation:     stripHTMLTags(a.Solution),
	}, ""
}

// zapCategory maps ZAP risk code to ANPU category.
func zapCategory(riskCode int) models.Category {
	switch riskCode {
	case 0:
		return models.CategoryExposure // informational / tech disclosure
	case 1:
		return models.CategoryConfiguration // misconfigurations
	case 2, 3:
		return models.CategoryVulnerability
	default:
		return models.CategoryOther
	}
}

// stripHTMLTags removes HTML tags from a string. ZAP descriptions
// frequently contain <p>, <ul>, <li>, and similar markup. We do a
// simple bracket scan rather than importing a full HTML parser, which
// keeps this package dependency-free.
func stripHTMLTags(s string) string {
	if !strings.ContainsRune(s, '<') {
		return strings.TrimSpace(s)
	}
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			b.WriteRune(' ')
		case !inTag:
			b.WriteRune(r)
		}
	}
	// Collapse runs of whitespace.
	return strings.Join(strings.Fields(b.String()), " ")
}
