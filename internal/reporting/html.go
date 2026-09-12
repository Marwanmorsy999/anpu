package reporting

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"time"

	"github.com/Marwanmorsy999/anpu/pkg/models"
	"github.com/Marwanmorsy999/anpu/pkg/version"
)

// htmlReportTemplate renders a single, self-contained HTML report (all
// CSS inline, no external requests) so it can be opened and shared as a
// standalone file.
const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ANPU Security Report — {{.Summary.Target}}</title>
<style>
  :root {
    --bg: #080a0f; --panel: #11141c; --panel-2: #0e1118; --border: #1e2430; --border-2: #252d3d;
    --text: #e8ecf3; --muted: #8a94ad; --faint: #5b647c;
    --critical: #ff3b3b; --high: #ff7a18; --medium: #eab308; --low: #3b82f6; --info: #6b7280;
    --accent: #22d3ee; --accent-2: #a78bfa;
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body { margin:0; background: var(--bg); color: var(--text); font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; line-height:1.6; -webkit-font-smoothing: antialiased; }
  .container { max-width: 1280px; margin: 0 auto; padding: 40px 28px 80px; }
  @media (min-width: 1600px) { .container { max-width: 1400px; } }
  header.report-header { padding-bottom: 28px; margin-bottom: 36px; border-bottom: 1px solid var(--border); }
  .brand { font-size: 30px; font-weight: 800; letter-spacing: 0.12em; color: var(--text); display:flex; align-items:center; gap:12px; }
  .brand::before { content:""; width:10px; height:10px; border-radius:50%; background: var(--accent); box-shadow: 0 0 12px rgba(34,211,238,0.6); }
  .brand small { font-size: 11px; font-weight: 600; letter-spacing: 0.14em; color: var(--muted); border:1px solid var(--border); padding:2px 8px; border-radius:999px; }
  .tagline { color: var(--muted); font-size: 13.5px; margin-top: 6px; letter-spacing: 0.01em; }
  .meta-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 14px; margin-top:22px; }
  .meta-item { background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%); border:1px solid var(--border); border-radius:12px; padding:14px 16px; }
  .meta-item .label { color: var(--faint); font-size: 10.5px; text-transform:uppercase; letter-spacing:.08em; font-weight:600; }
  .meta-item .value { font-size: 15px; font-weight:600; margin-top:4px; word-break:break-all; letter-spacing: -0.01em; }
  .risk-score { font-size: 44px; font-weight:800; letter-spacing:-0.03em; line-height:1; }
  .grade-badge { display:inline-block; margin-top:6px; font-size:11px; font-weight:700; letter-spacing:0.08em; text-transform:uppercase; color: var(--muted); border:1px solid var(--border); padding:3px 8px; border-radius:999px; background: var(--panel); }
  section { margin-bottom: 44px; }
  h2 { font-size: 13px; font-weight:700; letter-spacing:0.08em; text-transform:uppercase; color: var(--muted); border-bottom: none; padding-bottom: 0; margin-bottom:18px; display:flex; align-items:center; gap:10px; }
  h2::before { content:""; width:3px; height:14px; border-radius:999px; background: var(--accent); opacity:0.9; }
  .sev-summary { display:flex; gap:14px; flex-wrap:wrap; }
  .sev-pill { flex:1 1 140px; border-radius: 14px; padding: 16px 18px; min-width:120px; border:1px solid var(--border); background: var(--panel); transition: transform 0.15s ease; }
  .sev-pill:hover { transform: translateY(-1px); border-color: var(--border-2); }
  .sev-pill .count { font-size:28px; font-weight:800; letter-spacing:-0.02em; }
  .sev-pill .label { font-size:10.5px; text-transform:uppercase; color:var(--muted); letter-spacing:.08em; font-weight:600; margin-top:2px; }
  .sev-critical { border-top: 2px solid var(--critical); } .sev-critical .count { color: var(--critical); }
  .sev-high { border-top: 2px solid var(--high); } .sev-high .count { color: var(--high); }
  .sev-medium { border-top: 2px solid var(--medium); } .sev-medium .count { color: var(--medium); }
  .sev-low { border-top: 2px solid var(--low); } .sev-low .count { color: var(--low); }
  .sev-info { border-top: 2px solid var(--info); } .sev-info .count { color: var(--info); }
  table { width:100%; border-collapse: separate; border-spacing:0; font-size: 13px; border:1px solid var(--border); border-radius:10px; overflow:hidden; }
  th, td { text-align:left; padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align:top; }
  th { color: var(--faint); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:.06em; background: var(--panel-2); }
  tr:last-child td { border-bottom: none; }
  .badge { display:inline-block; border-radius: 999px; padding: 3px 9px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.03em; }
  .badge-critical { background: rgba(255,59,59,.14); color: var(--critical); border:1px solid rgba(255,59,59,.22); }
  .badge-high { background: rgba(255,122,24,.14); color: var(--high); border:1px solid rgba(255,122,24,.22); }
  .badge-medium { background: rgba(234,179,8,.14); color: var(--medium); border:1px solid rgba(234,179,8,.22); }
  .badge-low { background: rgba(59,130,246,.14); color: var(--low); border:1px solid rgba(59,130,246,.22); }
  .badge-info { background: rgba(107,114,128,.18); color: var(--muted); border:1px solid var(--border); }
  .finding { background: var(--panel); border:1px solid var(--border); border-radius:14px; padding:20px 22px; margin-bottom:16px; box-shadow: 0 1px 0 rgba(0,0,0,0.2); }
  .finding-title { font-size:15.5px; font-weight:700; margin-bottom:8px; letter-spacing:-0.01em; }
  .finding-meta { display:flex; gap:8px; align-items:center; margin-bottom:12px; flex-wrap:wrap;}
  .finding-field { margin-top:12px; }
  .finding-field .field-label { font-size:11px; text-transform:uppercase; color: var(--faint); letter-spacing:.07em; margin-bottom:4px; font-weight:600; }
  .finding-field > div:not(.field-label) { font-size:13.5px; color: var(--text); }
  .evidence-box { background: #07090d; border:1px solid var(--border); border-radius:10px; padding:10px 12px; font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12.5px; white-space:pre-wrap; word-break:break-word; color:#a7f3d0; line-height:1.5; }
  .evidence-unavailable { color: var(--muted); font-style: italic; }
  .refs a { color: var(--accent); text-decoration:none; font-size:12.5px; }
  .refs a:hover { text-decoration: underline; }
  .warn-box { background: rgba(234,179,8,.07); border:1px solid rgba(234,179,8,.28); border-radius:10px; padding:14px 16px; color: #facc15; font-size:13px; margin-bottom: 22px;}
  .tech-grid { display:flex; flex-wrap:wrap; gap:10px; }
  .tech-chip { background: var(--panel); border:1px solid var(--border); border-radius: 999px; padding: 7px 14px; font-size:12.5px; }
  .tech-chip .tc-cat { color: var(--muted); font-size: 10.5px; margin-left:7px; font-weight:600; letter-spacing:0.04em; text-transform:uppercase;}
  footer { color: var(--muted); font-size:12px; text-align:center; margin-top: 64px; border-top:1px solid var(--border); padding-top:22px;}
  .score-source { color: var(--faint); font-size: 11.5px; margin-top:8px; font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace; background: var(--panel-2); border:1px solid var(--border); border-radius:8px; padding:8px 10px; display:inline-block;}
</style>
</head>
<body>
<div class="container">
  <header class="report-header">
    <div class="brand">ANPU <span style="font-size:14px;font-weight:400;letter-spacing:1px;color:var(--muted);">// Guardian</span></div>
    <div class="tagline">Guard what you build. — Web Security Intelligence Report</div>
    <div class="meta-grid">
      <div class="meta-item"><div class="label">Target</div><div class="value">{{.Summary.Target}}</div></div>
      <div class="meta-item"><div class="label">Scan Profile</div><div class="value">{{.Summary.Profile}}</div></div>
      <div class="meta-item"><div class="label">Scan Time</div><div class="value">{{.StartedAtFormatted}}</div></div>
      <div class="meta-item"><div class="label">Risk Score</div><div class="value risk-score">{{printf "%.1f" .Summary.RiskScore}}<span style="font-size:16px;color:var(--muted);">/10</span></div><div style="color:var(--muted);font-size:12px;margin-top:3px;">Grade {{.RiskGrade}}</div></div>
    </div>
  </header>

  {{if .Summary.Warnings}}
  <div class="warn-box">
    <strong>Notes:</strong>
    <ul>
    {{range .Summary.Warnings}}<li>{{.}}</li>{{end}}
    </ul>
  </div>
  {{end}}

  <section>
    <h2>Risk Summary</h2>
    <div class="sev-summary">
      <div class="sev-pill sev-critical"><div class="count">{{.CriticalCount}}</div><div class="label">Critical</div></div>
      <div class="sev-pill sev-high"><div class="count">{{.HighCount}}</div><div class="label">High</div></div>
      <div class="sev-pill sev-medium"><div class="count">{{.MediumCount}}</div><div class="label">Medium</div></div>
      <div class="sev-pill sev-low"><div class="count">{{.LowCount}}</div><div class="label">Low</div></div>
      <div class="sev-pill sev-info"><div class="count">{{.InfoCount}}</div><div class="label">Info</div></div>
    </div>
  </section>

  <section>
    <h2>Attack Surface — Technologies</h2>
    {{if .Summary.Technologies}}
    <div class="tech-grid">
      {{range .Summary.Technologies}}
      <div class="tech-chip">{{.Name}}{{if .Version}} v{{.Version}}{{end}}<span class="tc-cat">{{.Category}}</span></div>
      {{end}}
    </div>
    {{else}}
    <p style="color:var(--muted)">No specific technologies were confidently identified.</p>
    {{end}}
  </section>

  <section>
    <h2>Attack Surface — Endpoints ({{len .Summary.Endpoints}})</h2>
    {{if .Summary.Endpoints}}
    <table>
      <tr><th>URL</th><th>Category</th><th>Sources</th></tr>
      {{range .Summary.Endpoints}}
      <tr><td>{{.URL}}</td><td>{{.Category}}</td><td>{{join .Sources ", "}}</td></tr>
      {{end}}
    </table>
    {{else}}
    <p style="color:var(--muted)">No endpoints were discovered.</p>
    {{end}}
  </section>

  <section>
    <h2>Findings ({{len .Summary.Findings}})</h2>
    {{range .Summary.Findings}}
    <div class="finding">
      <div class="finding-title">{{.Title}}</div>
      <div class="finding-meta">
        <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
        <span class="badge badge-info" style="background:rgba(255,255,255,.06);color:var(--muted)">confidence: {{.Confidence}}</span>
        <span class="badge badge-info" style="background:rgba(255,255,255,.06);color:var(--muted)">{{.Category}}</span>
        {{if .CWE}}<span class="badge badge-info" style="background:rgba(255,255,255,.06);color:var(--muted)">{{.CWE}}</span>{{end}}
      </div>

      {{if .URL}}<div class="finding-field"><div class="field-label">Affected URL</div><div>{{.URL}}</div></div>{{end}}

      <div class="finding-field"><div class="field-label">Description</div>{{if .Description}}<div>{{.Description}}</div>{{else}}<div class="evidence-unavailable">No description provided by the detecting engine.</div>{{end}}</div>

      <div class="finding-field">
        <div class="field-label">Evidence</div>
        {{if .Evidence.Unavailable}}
          <div class="evidence-box evidence-unavailable">Evidence unavailable</div>
        {{else if .Evidence.Observed}}
          <div class="evidence-box">{{if .Evidence.Location}}[{{.Evidence.Location}}]&#10;{{end}}{{.Evidence.Observed}}</div>
        {{else}}
          <div class="evidence-box evidence-unavailable">Evidence unavailable</div>
        {{end}}
      </div>

      {{if .EvidenceBundle}}
      <div class="finding-field">
        <div class="field-label">Evidence Bundle {{if .EvidenceBundle.NeedsReview}}<span class="badge badge-high" style="margin-left:8px;">needs review</span> {{if .EvidenceBundle.Technique}}<span class="badge badge-info">{{.EvidenceBundle.Technique}}</span>{{end}}{{end}}</div>
        {{if .EvidenceBundle.Curl}}<div class="field-label" style="margin-top:8px;">Repro</div><div class="evidence-box" style="color:#93c5fd;">{{.EvidenceBundle.Curl}}</div>{{end}}
        {{if .EvidenceBundle.RequestURL}}<div style="font-size:12px;color:var(--muted);margin-top:6px;">{{.EvidenceBundle.RequestMethod}} {{.EvidenceBundle.RequestURL}} {{if .EvidenceBundle.ResponseStatus}}→ {{.EvidenceBundle.ResponseStatus}}{{end}}</div>{{end}}
        {{if .EvidenceBundle.ResponseSnippets}}<div class="field-label" style="margin-top:8px;">Response snippets (200 chars, redacted)</div>{{range .EvidenceBundle.ResponseSnippets}}<div class="evidence-box" style="margin-top:6px;">{{.}}</div>{{end}}{{end}}
        {{if .EvidenceBundle.Snippets}}<div class="field-label" style="margin-top:8px;">Differential snippets</div>{{range .EvidenceBundle.Snippets}}<div class="evidence-box" style="margin-top:6px;">{{.}}</div>{{end}}{{end}}
        <div style="font-size:11.5px;color:var(--faint);margin-top:8px;border-left:2px solid var(--border);padding-left:8px;">FP disclaimer: single-technique differentials are capped at Medium and tagged for review. 200×3 same CT + random control + bundle required for fully earned High/High. Verify manually before action.</div>
      </div>
      {{end}}

      {{if .Impact}}<div class="finding-field"><div class="field-label">Impact</div><div>{{.Impact}}</div></div>{{end}}
      {{if .Remediation}}<div class="finding-field"><div class="field-label">Remediation</div><div>{{.Remediation}}</div></div>{{end}}

      <div class="finding-field">
        <div class="field-label">Source</div>
        <div>{{.Source}}{{if gt (len .MergedFrom) 1}} (corroborated by {{len .MergedFrom}} independent detections){{end}}</div>
      </div>

      <div class="finding-field">
        <div class="field-label">Risk Score</div>
        <div>{{printf "%.1f" .RiskScore}}/10</div>
        <div class="score-source">{{.ScoreExplanation}}</div>
      </div>

      {{if .References}}
      <div class="finding-field refs">
        <div class="field-label">References</div>
        {{range .References}}<div><a href="{{.}}" target="_blank" rel="noopener">{{.}}</a></div>{{end}}
      </div>
      {{end}}
    </div>
    {{end}}
  </section>

  {{if .Summary.PhaseTimings}}
  <section>
    <h2>Pipeline phases</h2>
    <table>
      <tr><th>Phase</th><th>Wall time</th><th>Stages</th></tr>
      {{range .Summary.PhaseTimings}}
      <tr><td>{{.Phase}}</td><td>{{printf "%.1f" .Seconds}}s</td><td>{{.Stages}}</td></tr>
      {{end}}
    </table>
    {{if .Summary.SlowestStages}}
    <h3>Slowest stages (top 5, stage wall time)</h3>
    <table>
      <tr><th>Stage</th><th>Wall time</th></tr>
      {{range .Summary.SlowestStages}}
      <tr><td>{{.Stage}}</td><td>{{printf "%.1f" .Seconds}}s</td></tr>
      {{end}}
    </table>
    {{end}}
  </section>
  {{end}}

  {{if .Summary.CodeFindings}}
  <section>
    <h2>Appendix — Local code scope ({{len .Summary.CodeFindings}} findings, unscored)</h2>
    <p style="color:var(--muted)">These findings describe operator-supplied local material (code checkout, APK), <strong>not</strong> the scan target. They are excluded from the grade, counts, and risk score above — triage them against the codebase, not the site.</p>
    {{range .Summary.CodeFindings}}
    <div class="finding">
      <div class="finding-title">{{.Title}}</div>
      <div class="finding-meta">
        <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
        <span class="badge badge-info" style="background:rgba(255,255,255,.06);color:var(--muted)">confidence: {{.Confidence}}</span>
        <span class="badge badge-info" style="background:rgba(255,255,255,.06);color:var(--muted)">{{.Category}}</span>
        <span class="badge badge-info" style="background:rgba(255,255,255,.06);color:var(--muted)">local-code</span>
        {{if .CWE}}<span class="badge badge-info" style="background:rgba(255,255,255,.06);color:var(--muted)">{{.CWE}}</span>{{end}}
      </div>
      {{if .Evidence.Observed}}<div class="finding-field"><div class="field-label">Evidence</div><div class="evidence-box">[{{.Evidence.Location}}]&#10;{{.Evidence.Observed}}</div></div>{{end}}
      {{if .Remediation}}<div class="finding-field"><div class="field-label">Remediation</div><div>{{.Remediation}}</div></div>{{end}}
      <div class="finding-field"><div class="field-label">Source</div><div>{{.Source}} — {{.DetectionMethod}}</div></div>
    </div>
    {{end}}
  </section>
  {{end}}

  <footer>
    Generated by ANPU {{.Version}} — for use only against targets you own or are explicitly authorized to test.
  </footer>
</div>
</body>
</html>`

type htmlReportData struct {
	Summary            *models.ScanSummary
	StartedAtFormatted string
	Version            string
	RiskGrade          string
	CriticalCount      int
	HighCount          int
	MediumCount        int
	LowCount           int
	InfoCount          int
}

var reportFuncs = template.FuncMap{
	"join": func(items []string, sep string) string {
		out := ""
		for i, s := range items {
			if i > 0 {
				out += sep
			}
			out += s
		}
		return out
	},
}

// RiskGrade converts the transparent 0-10 aggregate score into a compact grade.
func RiskGrade(score float64) string {
	switch {
	case score >= 9:
		return "F"
	case score >= 8:
		return "E"
	case score >= 7:
		return "D"
	case score >= 5.5:
		return "C"
	case score >= 3.5:
		return "B"
	default:
		return "A"
	}
}

// WriteHTML renders the polished HTML security report to path.
// Findings render severity-first (critical → info, stable by ID) so
// the report reads worst-first regardless of pipeline stage order.
func WriteHTML(summary *models.ScanSummary, path string) error {
	tmpl, err := template.New("report").Funcs(reportFuncs).Parse(htmlReportTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML report template: %w", err)
	}

	if summary.SeverityCounts == nil {
		summary.RecomputeSeverityCounts()
	}

	ordered := *summary
	ordered.Findings = append([]models.Finding(nil), summary.Findings...)
	sort.Slice(ordered.Findings, func(i, j int) bool {
		if ordered.Findings[i].Severity.Rank() != ordered.Findings[j].Severity.Rank() {
			return ordered.Findings[i].Severity.Rank() > ordered.Findings[j].Severity.Rank()
		}
		return ordered.Findings[i].ID < ordered.Findings[j].ID
	})

	data := htmlReportData{
		Summary:            &ordered,
		StartedAtFormatted: summary.StartedAt.Format(time.RFC1123),
		Version:            version.Version,
		RiskGrade:          RiskGrade(summary.RiskScore),
		CriticalCount:      summary.SeverityCounts[models.SeverityCritical],
		HighCount:          summary.SeverityCounts[models.SeverityHigh],
		MediumCount:        summary.SeverityCounts[models.SeverityMedium],
		LowCount:           summary.SeverityCounts[models.SeverityLow],
		InfoCount:          summary.SeverityCounts[models.SeverityInfo],
	}

	f, err := os.Create(path) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
	if err != nil {
		return fmt.Errorf("creating HTML report file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("rendering HTML report: %w", err)
	}
	return nil
}
