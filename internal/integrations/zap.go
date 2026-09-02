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
	"os/exec"
	"strconv"
	"strings"
	"time"

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

// resolvedDockerPath returns the docker binary path.
func (z *ZapScanner) resolvedDockerPath() string {
	if z.DockerBinary != "" {
		return z.DockerBinary
	}
	if path, err := exec.LookPath("docker"); err == nil {
		return path
	}
	return "docker"
}

// resolvedZapPath returns the zap.sh/zap.bat binary path.
func (z *ZapScanner) resolvedZapPath() string {
	if z.ZapBinary != "" {
		return z.ZapBinary
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
		cmd := exec.Command(p, "-version")
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
	cmd := exec.CommandContext(checkCtx, z.resolvedDockerPath(), "info", "--format", "{{.ServerVersion}}")
	return cmd.Run() == nil
}

// zapBinaryAvailable reports whether a local zap.sh installation is present.
func (z *ZapScanner) zapBinaryAvailable() bool {
	path := z.resolvedZapPath()
	if path == "" {
		return false
	}
	cmd := exec.Command(path, "-version")
	return cmd.Run() == nil
}

// Available returns true when either Docker (with the ZAP image pullable)
// or a local zap.sh binary is present. The image pull itself is not
// attempted here — that would be too slow and might fail on air-gapped
// systems; we just check that the daemon is up.
func (z *ZapScanner) Available(ctx context.Context) bool {
	return z.dockerAvailable(ctx) || z.zapBinaryAvailable()
}

// Run invokes ZAP against the scan target and converts its JSON report
// into ANPU findings. Docker mode is preferred; local binary is used as
// a fallback. If neither is available, a warning is returned and the
// pipeline continues normally.
func (z *ZapScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	useDocker := z.dockerAvailable(ctx)
	useLocal := !useDocker && z.zapBinaryAvailable()

	if !useDocker && !useLocal {
		return scanner.StageResult{
			Warnings: []string{
				"ZAP is not available: install Docker (preferred) or OWASP ZAP locally to enable this stage. " +
					"Docker: https://docs.docker.com/get-docker/ — ZAP: https://www.zaproxy.org/download/",
			},
		}, nil
	}

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
// Baseline (safe/standard) = passive + ajax spider, no active scan.
// Full (deep) = active spider + active scan.
func scanScript(profile models.Profile) string {
	if profile == models.ProfileDeep {
		return "zap-full-scan.py"
	}
	return "zap-baseline.py"
}

// runDocker runs ZAP via `docker run`. It mounts nothing and passes the
// target URL directly; ZAP writes its JSON report to stdout via -J stdout.
func (z *ZapScanner) runDocker(ctx context.Context, sc *scanner.ScanContext) ([]byte, []string, error) {
	script := scanScript(sc.Config.Profile)
	args := []string{
		"run", "--rm",
		// No bind mounts — read stdout directly.
		z.dockerImage(),
		script,
		"-t", sc.Target.Raw,
		"-J", "/dev/stdout", // JSON to stdout
		"-I", // don't fail on warn
		"-q", // suppress progress to stderr
	}

	cmd := exec.CommandContext(ctx, z.resolvedDockerPath(), args...)
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
	_ = script // script-name awareness reserved for future flag expansion

	cmd := exec.CommandContext(ctx, zapPath, args...)
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
