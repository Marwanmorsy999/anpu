// Package integrations — generic_parse.go: output parsers for the
// data-driven external wrappers. parseSpecial handles tools with known
// text/JSON shapes; parseJSONFindings does a best-effort generic walk
// for JSON-emitting tools. Both are pure functions over captured bytes
// (unit-tested with fixture output, no binaries needed).
package integrations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

// parseSpecial dispatches per-tool structured parsing. Unknown tools
// return nothing (the generic miners still run).
func parseSpecial(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	switch spec.Name {
	case "ffuf", "gobuster", "wfuzz", "dirsearch":
		return parseFuzzer(spec, sc, out, repro)
	case "nikto":
		return parseNikto(spec, sc, out, repro)
	case "nmap", "masscan", "rustscan":
		return parsePorts(spec, sc, out, repro)
	case "wpscan":
		return parseWpscan(spec, sc, out, repro)
	case "semgrep":
		return parseSemgrep(spec, sc, out, repro)
	case "trivy":
		return parseTrivy(spec, sc, out, repro)
	case "osv-scanner":
		return parseOSVScan(spec, sc, out, repro)
	case "grype":
		return parseGrype(spec, sc, out, repro)
	case "searchsploit":
		return parseSearchsploit(spec, sc, out, repro)
	case "subzy", "subjack":
		return parseTakeoverText(spec, sc, out, repro)
	case "whatweb":
		return parseWhatweb(spec, sc, out, repro)
	case "unfurl":
		return parseUnfurlKeys(spec, sc, out, repro)
	case "gitleaks", "trufflehog":
		return parseSecretsText(spec, sc, out, repro)
	case "openredirex":
		return parseOpenRedirex(spec, sc, out, repro)
	case "dotdotpwn":
		return parseDotdotpwn(spec, sc, out, repro)
	}
	return nil, nil
}

func toolFinding(spec *ToolSpec, sc *scanner.ScanContext, id, title, desc string, sev models.Severity, observed, repro string) models.Finding {
	return models.Finding{
		ID: spec.Name + "-" + id, Title: title, Description: desc,
		Severity: sev, Confidence: models.ConfidenceHigh, Category: models.CategoryExposure,
		Target:   sc.Target.Raw,
		Evidence: models.Evidence{Observed: trimMiddle(observed, 300), Location: "external " + spec.Binary + " output"},
		Source:   models.SourceCustom, DetectionMethod: "external: " + trimMiddle(repro, 300),
	}
}

var (
	ffufRe      = regexp.MustCompile(`(?im)^(\S+?)\s+\[Status:\s*(\d+),\s*(?:Size|Length):\s*(\d+)`)
	gobusterRe  = regexp.MustCompile(`(?im)^(\S+)\s+\(Status:\s*(\d+)\)`)
	wfuzzRe     = regexp.MustCompile(`(?im)^\d+:\s+C=(\d+)\s+\d+\s+L\s+\d+\s+W\s+\d+\s+Ch\s+"([^"]+)"`)
	dirsearchRe = regexp.MustCompile(`(?im)^\[.*?\]\s+(\d+)\s+-\s+\S+\s+-\s+(\S+)`)
)

// parseFuzzer turns dir-fuzzer hits into Info findings + endpoints are
// mined generically. 401/403 hits are Low (access-control review).
func parseFuzzer(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	type hit struct{ path, status string }
	var hits []hit
	text := string(out)
	for _, m := range ffufRe.FindAllStringSubmatch(text, -1) {
		hits = append(hits, hit{m[1], m[2]})
	}
	for _, m := range gobusterRe.FindAllStringSubmatch(text, -1) {
		hits = append(hits, hit{m[1], m[2]})
	}
	for _, m := range wfuzzRe.FindAllStringSubmatch(text, -1) {
		if m[1] == "404" {
			continue
		}
		hits = append(hits, hit{m[2], m[1]})
	}
	for _, m := range dirsearchRe.FindAllStringSubmatch(text, -1) {
		if m[1] == "404" {
			continue
		}
		hits = append(hits, hit{m[2], m[1]})
	}
	var findings []models.Finding
	for i, h := range hits {
		if i >= maxToolFinds {
			break
		}
		if h.status == "404" {
			continue
		}
		sev := models.SeverityInfo
		if h.status == "401" || h.status == "403" {
			sev = models.SeverityLow
		}
		findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("hit-%d", i+1),
			fmt.Sprintf("Fuzzer hit: %s → %s", h.path, h.status),
			fmt.Sprintf("External fuzzer %s reports %s at status %s. Verify manually; 401/403 deserve access-control review. Reproduce: %s.", spec.Binary, h.path, h.status, trimMiddle(repro, 200)),
			sev, fmt.Sprintf("%s → %s", h.path, h.status), repro))
	}
	return findings, nil
}

// parseNikto maps "+ " lines to Low/Info findings (cap 10).
func parseNikto(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var findings []models.Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+ ") || len(findings) >= maxToolFinds {
			continue
		}
		body := strings.TrimPrefix(line, "+ ")
		sev := models.SeverityInfo
		l := strings.ToLower(body)
		if strings.Contains(l, "vulnerab") || strings.Contains(l, "outdated") || strings.Contains(l, "osvdb-") {
			sev = models.SeverityLow
		}
		findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("item-%d", len(findings)+1),
			"Nikto: "+trimMiddle(body, 120),
			"Nikto check (no-DoS tuning) reported this item. Triage manually; Nikto output includes/quotes banners that may be false positives.",
			sev, body, repro))
	}
	return findings, nil
}

var nmapOpenRe = regexp.MustCompile(`(?m)^Host:\s*(\S+).*?Ports:\s*(.+)$`)

// parsePorts handles nmap -oG, masscan -oL, rustscan script lines.
func parsePorts(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var findings []models.Finding
	text := string(out)
	openRe := regexp.MustCompile(`(\d{1,5})/open/(\w+)`)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// masscan -oL: "open tcp 80 1.2.3.4 12345".
		if m := regexp.MustCompile(`(?i)^open\s+(\w+)\s+(\d+)\s+(\S+)`).FindStringSubmatch(line); m != nil {
			findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("port-%s-%s", m[2], m[1]),
				fmt.Sprintf("Open port: %s/%s on %s", m[2], m[1], m[3]),
				fmt.Sprintf("External scanner %s reports %s/%s open on %s. Corroborate with service banners before acting.", spec.Binary, m[2], m[1], m[3]),
				models.SeverityInfo, line, repro))
		} else if nmapOpenRe.MatchString(line) {
			for _, m := range openRe.FindAllStringSubmatch(line, -1) {
				findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("port-%s-%s", m[1], m[2]),
					fmt.Sprintf("Open port: %s/%s", m[1], m[2]),
					fmt.Sprintf("External scanner %s reports %s/%s open. Corroborate before acting.", spec.Binary, m[1], m[2]),
					models.SeverityInfo, line, repro))
			}
		} else if m := regexp.MustCompile(`(?i)^open\s+(\S+):(\d+)$`).FindStringSubmatch(line); m != nil {
			// rustscan script output.
			findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("port-%s", m[2]),
				fmt.Sprintf("Open port: %s on %s", m[2], m[1]),
				fmt.Sprintf("External scanner %s reports port %s open on %s.", spec.Binary, m[2], m[1]),
				models.SeverityInfo, line, repro))
		}
		if len(findings) >= 15 {
			break
		}
	}
	return findings, nil
}

// parseWpscan extracts version → Technology plus finding counts.
func parseWpscan(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var doc struct {
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
		InterestingFindings []struct {
			Type    string `json:"type"`
			FoundBy string `json:"found_by"`
		} `json:"interesting_findings"`
	}
	var techs []models.Technology
	var findings []models.Finding
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, nil
	}
	if doc.Version.Number != "" {
		techs = append(techs, models.Technology{Name: "WordPress", Version: doc.Version.Number, Category: "cms", Confidence: 0.95,
			Evidence: models.Evidence{Observed: "version " + doc.Version.Number, Location: "wpscan JSON"}})
		findings = append(findings, toolFinding(spec, sc, "version",
			"WordPress "+doc.Version.Number+" (wpscan enum, keyless)",
			"WPScan enumeration (no API token) identified the core version plus finding counts below. Vuln-database correlation needs a token and is out of scope.",
			models.SeverityInfo, "version "+doc.Version.Number, repro))
	}
	if len(doc.InterestingFindings) > 0 {
		findings = append(findings, toolFinding(spec, sc, "interesting",
			fmt.Sprintf("WPScan: %d interesting finding(s)", len(doc.InterestingFindings)),
			"WPScan lists exposed WP surfaces (readme, xmlrpc, users). Review each in the raw JSON.",
			models.SeverityLow, fmt.Sprintf("%d interesting findings", len(doc.InterestingFindings)), repro))
	}
	return findings, techs
}

// parseSemgrep maps results[] severities (cap 10).
func parseSemgrep(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var doc struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, nil
	}
	sevMap := map[string]models.Severity{"ERROR": models.SeverityHigh, "WARNING": models.SeverityMedium, "INFO": models.SeverityInfo}
	var findings []models.Finding
	for i, r := range doc.Results {
		if i >= maxToolFinds {
			break
		}
		sev, ok := sevMap[strings.ToUpper(r.Extra.Severity)]
		if !ok {
			sev = models.SeverityMedium
		}
		findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("rule-%d", i+1),
			"Semgrep "+r.CheckID+" at "+r.Path+":"+strconv.Itoa(r.Start.Line),
			"Semgrep SAST (free rules) flagged this location. Triage in code context; SAST output includes false positives. "+trimMiddle(r.Extra.Message, 200),
			sev, r.CheckID+" "+r.Path, repro))
	}
	return findings, nil
}

// parseTrivy maps vulnerability entries (cap 10).
func parseTrivy(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var doc struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				Severity         string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, nil
	}
	var findings []models.Finding
	for _, res := range doc.Results {
		for _, v := range res.Vulnerabilities {
			if len(findings) >= maxToolFinds {
				break
			}
			findings = append(findings, toolFinding(spec, sc, v.VulnerabilityID,
				fmt.Sprintf("Trivy %s in %s %s (%s)", v.VulnerabilityID, v.PkgName, v.InstalledVersion, res.Target),
				"Trivy local-DB match. Upgrade the package per the advisory; confirm reachability before prioritizing.",
				mapSeverity(v.Severity), v.VulnerabilityID+" "+v.PkgName, repro))
		}
	}
	return findings, nil
}

// parseOSVScan maps osv-scanner JSON (cap 10).
func parseOSVScan(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var doc struct {
		Results []struct {
			Packages []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID      string `json:"id"`
					Summary string `json:"summary"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, nil
	}
	var findings []models.Finding
	for _, res := range doc.Results {
		for _, p := range res.Packages {
			for _, v := range p.Vulnerabilities {
				if len(findings) >= maxToolFinds {
					break
				}
				findings = append(findings, toolFinding(spec, sc, v.ID,
					fmt.Sprintf("OSV %s in %s", v.ID, p.Package.Name),
					"OSV.dev keyless match. "+trimMiddle(v.Summary, 200),
					models.SeverityMedium, v.ID+" "+p.Package.Name, repro))
			}
		}
	}
	return findings, nil
}

// parseGrype maps matches[] (cap 10).
func parseGrype(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, nil
	}
	var findings []models.Finding
	for i, m := range doc.Matches {
		if i >= maxToolFinds {
			break
		}
		findings = append(findings, toolFinding(spec, sc, m.Vulnerability.ID,
			fmt.Sprintf("Grype %s in %s %s", m.Vulnerability.ID, m.Artifact.Name, m.Artifact.Version),
			"Grype local-DB match. Confirm reachability before prioritizing.",
			mapSeverity(m.Vulnerability.Severity), m.Vulnerability.ID, repro))
	}
	return findings, nil
}

// parseSearchsploit maps RESULTS_EXPLOIT[] (mapping only, never run).
func parseSearchsploit(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var doc struct {
		Results []struct {
			Title string `json:"Title"`
			Path  string `json:"Path"`
		} `json:"RESULTS_EXPLOIT"`
	}
	var alt struct {
		Results []struct {
			Title string `json:"Title"`
			Path  string `json:"Path"`
		} `json:"RESULTS"`
	}
	var findings []models.Finding
	if err := json.Unmarshal(out, &doc); err == nil {
		for i, r := range doc.Results {
			if i >= 3 {
				break
			}
			findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("exploit-%d", len(findings)+1),
				"Public exploit exists (mapping only): "+trimMiddle(r.Title, 100),
				"Local Exploit-DB maps a public exploit to fingerprinted software ("+r.Path+"). Mapping only — exploits are never executed. Patch and verify version first.",
				models.SeverityMedium, r.Title, repro))
		}
	} else if err := json.Unmarshal(out, &alt); err == nil {
		for i, r := range alt.Results {
			if i >= 3 {
				break
			}
			findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("exploit-%d", len(findings)+1),
				"Public exploit exists (mapping only): "+trimMiddle(r.Title, 100),
				"Local Exploit-DB mapping only — never executed.",
				models.SeverityMedium, r.Title, repro))
		}
	}
	return findings, nil
}

// parseTakeoverText maps subzy/subjack vulnerable lines (High).
func parseTakeoverText(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var findings []models.Finding
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.ToLower(line)
		if !strings.Contains(l, "vulnerable") {
			continue
		}
		// Guard against help/usage text ("potentially vulnerable",
		// "--hide_fails") and negative verdicts matching the substring.
		if strings.Contains(l, "not vulnerable") || strings.Contains(l, "potential") ||
			strings.Contains(l, "hide_fail") || strings.Contains(l, "hide-fail") {
			continue
		}
		if len(findings) >= maxToolFinds {
			break
		}
		findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("takeover-%d", len(findings)+1),
			strings.TrimSpace(line),
			"External takeover corroboration flags this hostname. Claim or remove the DNS record. Corroborate with ANPU's native fingerprint before acting.",
			models.SeverityHigh, strings.TrimSpace(line), repro))
	}
	return findings, nil
}

// parseWhatweb extracts [bracket] tech tokens into Technologies.
func parseWhatweb(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var techs []models.Technology
	re := regexp.MustCompile(`\[([^\]]+)\]`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(firstLines(out, 5), -1) {
		name := strings.TrimSpace(m[1])
		if name == "" || seen[name] || len(techs) >= 10 {
			continue
		}
		if strings.Contains(name, " ") && !strings.Contains(name, "/") {
			continue
		}
		seen[name] = true
		techs = append(techs, models.Technology{Name: name, Category: "other", Confidence: 0.6,
			Evidence: models.Evidence{Observed: "whatweb brief", Location: "external whatweb"}})
	}
	return nil, techs
}

// parseUnfurlKeys maps `unfurl -u keys` output (one query-string key
// per line) into a single Info finding carrying the observed key set.
func parseUnfurlKeys(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	seen := map[string]bool{}
	var keys []string
	for _, line := range strings.Split(string(out), "\n") {
		k := strings.TrimSpace(line)
		if k == "" || seen[k] || len(k) > 64 || strings.ContainsAny(k, " \t/:?#&=") {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
		if len(keys) >= 50 {
			break
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	f := toolFinding(spec, sc, "keys",
		fmt.Sprintf("Query parameter surface (%d keys)", len(keys)),
		fmt.Sprintf("unfurl extracted %d unique query-string keys from discovered URLs: %s. Native Params classifies each for injection relevance.",
			len(keys), strings.Join(keys, ", ")),
		models.SeverityInfo, strings.Join(keys, ", "), repro)
	return []models.Finding{f}, nil
}

// ansiCSIRe strips all terminal CSI escape sequences (colors, cursor
// moves, progress-bar rewrites) before line matching. Tools emit color
// even without a TTY when piped (wfuzz -c, nikto, feroxbuster), which
// otherwise breaks exact-spacing text regexes silently.
var ansiCSIRe = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]")

// stripANSI removes terminal escape sequences from tool output.
func stripANSI(out []byte) []byte {
	if !strings.Contains(string(out), "\x1b[") {
		return out
	}
	return []byte(ansiCSIRe.ReplaceAllString(string(out), ""))
}

// ansiRe is kept for the openredirex/dotdotpwn call sites below; new
// code should use stripANSI (full CSI coverage, not just SGR colors).
var ansiRe = ansiCSIRe

// parseOpenRedirex maps `[FOUND] <url> redirects to <chain>` lines to
// Medium findings (confirmed open redirect, same bar as redirectpack).
// [INFO] lines are redirect chains without an external landing — the
// generic URL miner still harvests any same-host URLs from them.
func parseOpenRedirex(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var findings []models.Finding
	for _, line := range strings.Split(ansiRe.ReplaceAllString(string(out), ""), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "[FOUND]") {
			continue
		}
		if len(findings) >= maxToolFinds {
			break
		}
		findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("open-redirect-%d", len(findings)+1),
			"Open redirect confirmed: "+trimMiddle(strings.TrimSpace(strings.Replace(line, "[FOUND]", "", 1)), 110),
			"External fuzzer openredirex followed a fuzzed parameter value to a redirect chain (see evidence). Validate redirect targets against an allowlist; the destination was followed, never weaponized.",
			models.SeverityMedium, strings.TrimSpace(line), repro))
	}
	return findings, nil
}

// dotdotpwnVulnRe matches dotdotpwn's verdict lines. Only VULNERABLE
// lines become findings; FALSE POSITIVE lines are the tool's own
// negative verdicts and stay out of the finding set.
var dotdotpwnVulnRe = regexp.MustCompile(`(?m)VULNERABLE!`)

// parseDotdotpwn maps `... <- VULNERABLE!` traversal verdicts to High
// findings (arbitrary file read primitive, same bar as lfipack-read).
func parseDotdotpwn(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var findings []models.Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !dotdotpwnVulnRe.MatchString(line) {
			continue
		}
		if len(findings) >= maxToolFinds {
			break
		}
		findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("traversal-%d", len(findings)+1),
			"Directory traversal confirmed: "+trimMiddle(line, 110),
			"External fuzzer dotdotpwn retrieved /etc/hosts content via traversal (read-only marker match vs localhost keyword). Map user input to an allowlist and deny traversals. File bodies are not stored.",
			models.SeverityHigh, line, repro))
	}
	return findings, nil
}

// parseSecretsText maps gitleaks/trufflehog findings (cap 10, High).
// It accepts a whole-document JSON array (gitleaks -f json pretty
// output) as well as line-delimited JSON objects.
func parseSecretsText(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) ([]models.Finding, []models.Technology) {
	var findings []models.Finding
	add := func(description, rule, file, detector string) {
		name := description
		if name == "" {
			name = detector
		}
		if name == "" {
			name = rule
		}
		if name == "" || len(findings) >= maxToolFinds {
			return
		}
		findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("secret-%d", len(findings)+1),
			"Secret in local code: "+trimMiddle(name, 100)+" ("+file+")",
			"Local-only secret scan hit. Values are never printed; rotate the credential and purge history. Local code scope only.",
			models.SeverityHigh, name, repro))
	}
	// secretName picks a printable label from known keys. Secret VALUES
	// (Secret, Raw, Match, Fingerprint content) are never labels — only
	// rule/file/detector/commit metadata is shown.
	secretName := func(m map[string]any) (description, rule, file, detector string) {
		str := func(keys ...string) string {
			for _, k := range keys {
				for mk, mv := range m {
					if strings.EqualFold(mk, k) {
						if s, ok := mv.(string); ok && strings.TrimSpace(s) != "" {
							return strings.TrimSpace(s)
						}
					}
				}
			}
			return ""
		}
		return str("Description", "description", "message", "rule", "RuleName"),
			str("RuleID", "rule_id", "check_id", "DetectorType", "rule"),
			str("File", "file", "path", "filename"),
			str("DetectorName", "detector", "detectorName", "Commit", "commit", "Fingerprint", "fingerprint")
	}
	decodeHit := func(data []byte) (description, rule, file, detector string, ok bool) {
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return "", "", "", "", false
		}
		description, rule, file, detector = secretName(m)
		return description, rule, file, detector, true
	}
	// Whole-document array first (gitleaks -f json pretty output).
	var arr []json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(out), &arr); err == nil {
		for _, raw := range arr {
			if d, r, f, det, ok := decodeHit(raw); ok {
				add(d, r, f, det)
			}
		}
		return findings, nil
	}
	// Line-delimited fallback (one object per line).
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if d, r, f, det, ok := decodeHit([]byte(line)); ok {
			add(d, r, f, det)
		}
	}
	return findings, nil
}

// jsonShapeWarning fires when a JSON-expecting tool emitted something
// that is not JSON at all (schema drift, version banner, table output
// instead of --json). Valid JSON with zero items stays silent — a clean
// tool is not an error. This turns silent-empty parses into a visible
// warning naming the tool and its size.
func jsonShapeWarning(spec *ToolSpec, out []byte) string {
	if spec == nil || !spec.JSON {
		return ""
	}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return ""
	}
	if bytes.HasPrefix(trimmed, []byte("{")) || bytes.HasPrefix(trimmed, []byte("[")) {
		var v any
		if err := json.Unmarshal(trimmed, &v); err == nil {
			return ""
		}
	}
	if len(trimmed) < 200 {
		return ""
	}
	return fmt.Sprintf("%s produced %d bytes ANPU could not structure as JSON (output shape changed? check %s version/flags) — URL/host miners still ran",
		spec.Name, len(trimmed), spec.Binary)
}

// parseJSONFindings is the best-effort generic walk for JSON-emitting
// tools: it collects url/host/severity/title-shaped fields.
func parseJSONFindings(spec *ToolSpec, sc *scanner.ScanContext, out []byte, repro string) []models.Finding {
	text := strings.TrimSpace(string(out))
	if text == "" || (!strings.HasPrefix(text, "{") && !strings.HasPrefix(text, "[")) {
		return nil
	}
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		return nil
	}
	type item struct{ title, url, sev string }
	var items []item
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			var title, url, sev string
			for k, val := range t {
				lk := strings.ToLower(k)
				s, _ := val.(string)
				switch lk {
				case "url", "matched-at", "link":
					url = s
				case "title", "name", "templateid", "template_id":
					title = s
				case "severity", "level":
					sev = s
				}
			}
			if title != "" || url != "" {
				items = append(items, item{title, url, sev})
				if len(items) >= maxToolFinds {
					return
				}
			}
			for _, val := range t {
				walk(val)
				if len(items) >= maxToolFinds {
					return
				}
			}
		case []any:
			for _, e := range t {
				walk(e)
				if len(items) >= maxToolFinds {
					return
				}
			}
		}
	}
	walk(v)
	var findings []models.Finding
	for i, it := range items {
		t := it.title
		if t == "" {
			t = it.url
		}
		if t == "" {
			continue
		}
		findings = append(findings, toolFinding(spec, sc, fmt.Sprintf("json-%d", i+1),
			spec.LabelName()+": "+trimMiddle(t, 110),
			"Structured output from "+spec.Binary+". Triage against the raw JSON.",
			mapSeverity(it.sev), t, repro))
	}
	return findings
}
