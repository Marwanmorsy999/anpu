package reporting

import (
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/anpu-project/anpu/pkg/models"
	"github.com/anpu-project/anpu/pkg/version"
)

// htmlReportTemplate renders a single, self-contained HTML report (all
// CSS inline, no external requests) so it can be opened and shared as a
// standalone file.
const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ANPU Security Report — {{.Summary.Target}}</title>
<style>
  :root {
    --bg: #0b0d12; --panel: #12151c; --border: #232833; --text: #e6e9ef; --muted: #8b93a5;
    --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #3b82f6; --info: #6b7280;
    --accent: #22d3ee;
  }
  * { box-sizing: border-box; }
  body { margin:0; background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; line-height:1.5; }
  .container { max-width: 1000px; margin: 0 auto; padding: 32px 20px 80px; }
  header.report-header { border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }
  .brand { font-size: 28px; font-weight: 800; letter-spacing: 2px; color: var(--accent); }
  .tagline { color: var(--muted); font-size: 13px; margin-top: 4px; }
  .meta-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr)); gap: 12px; margin-top:20px; }
  .meta-item { background: var(--panel); border:1px solid var(--border); border-radius:8px; padding:12px 14px; }
  .meta-item .label { color: var(--muted); font-size: 11px; text-transform:uppercase; letter-spacing:.06em; }
  .meta-item .value { font-size: 15px; font-weight:600; margin-top:2px; word-break:break-all; }
  .risk-score { font-size: 40px; font-weight:800; }
  section { margin-bottom: 40px; }
  h2 { font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom:16px; }
  .sev-summary { display:flex; gap:12px; flex-wrap:wrap; }
  .sev-pill { border-radius: 10px; padding: 14px 18px; min-width:110px; border:1px solid var(--border); background:var(--panel); }
  .sev-pill .count { font-size:26px; font-weight:800; }
  .sev-pill .label { font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.06em; }
  .sev-critical { border-left: 4px solid var(--critical); } .sev-critical .count { color: var(--critical); }
  .sev-high { border-left: 4px solid var(--high); } .sev-high .count { color: var(--high); }
  .sev-medium { border-left: 4px solid var(--medium); } .sev-medium .count { color: var(--medium); }
  .sev-low { border-left: 4px solid var(--low); } .sev-low .count { color: var(--low); }
  .sev-info { border-left: 4px solid var(--info); } .sev-info .count { color: var(--info); }
  table { width:100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align:left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align:top; }
  th { color: var(--muted); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:.05em; }
  .badge { display:inline-block; border-radius: 6px; padding: 2px 8px; font-size:11px; font-weight:700; text-transform:uppercase; }
  .badge-critical { background: rgba(239,68,68,.15); color: var(--critical); }
  .badge-high { background: rgba(249,115,22,.15); color: var(--high); }
  .badge-medium { background: rgba(234,179,8,.15); color: var(--medium); }
  .badge-low { background: rgba(59,130,246,.15); color: var(--low); }
  .badge-info { background: rgba(107,114,128,.2); color: var(--info); }
  .finding { background: var(--panel); border:1px solid var(--border); border-radius:10px; padding:18px 20px; margin-bottom:14px; }
  .finding-title { font-size:15px; font-weight:700; margin-bottom:6px; }
  .finding-meta { display:flex; gap:8px; align-items:center; margin-bottom:10px; flex-wrap:wrap;}
  .finding-field { margin-top:10px; }
  .finding-field .field-label { font-size:11px; text-transform:uppercase; color: var(--muted); letter-spacing:.05em; margin-bottom:2px; }
  .evidence-box { background:#0a0c10; border:1px solid var(--border); border-radius:6px; padding:8px 10px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12.5px; white-space:pre-wrap; word-break:break-word; color:#9ffcc0; }
  .evidence-unavailable { color: var(--muted); font-style: italic; }
  .refs a { color: var(--accent); text-decoration:none; font-size:12.5px; }
  .warn-box { background: rgba(234,179,8,.08); border:1px solid rgba(234,179,8,.35); border-radius:8px; padding:12px 16px; color: #eab308; font-size:13px; margin-bottom: 20px;}
  .tech-grid { display:flex; flex-wrap:wrap; gap:8px; }
  .tech-chip { background: var(--panel); border:1px solid var(--border); border-radius: 999px; padding: 6px 14px; font-size:12.5px; }
  .tech-chip .tc-cat { color: var(--muted); font-size: 10.5px; margin-left:6px;}
  footer { color: var(--muted); font-size:12px; text-align:center; margin-top: 60px; border-top:1px solid var(--border); padding-top:20px;}
  .score-source { color: var(--muted); font-size: 11.5px; margin-top:6px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;}
</style>
</head>
<body>
<div class="container">
  <header class="report-header">
    <div class="brand">ANPU</div>
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

      <div class="finding-field"><div class="field-label">Description</div><div>{{.Description}}</div></div>

      <div class="finding-field">
        <div class="field-label">Evidence</div>
        {{if .Evidence.Unavailable}}
          <div class="evidence-box evidence-unavailable">Evidence unavailable</div>
        {{else}}
          <div class="evidence-box">{{if .Evidence.Location}}[{{.Evidence.Location}}]&#10;{{end}}{{.Evidence.Observed}}</div>
        {{end}}
      </div>

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
func WriteHTML(summary *models.ScanSummary, path string) error {
	tmpl, err := template.New("report").Funcs(reportFuncs).Parse(htmlReportTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML report template: %w", err)
	}

	if summary.SeverityCounts == nil {
		summary.RecomputeSeverityCounts()
	}

	data := htmlReportData{
		Summary:            summary,
		StartedAtFormatted: summary.StartedAt.Format(time.RFC1123),
		Version:            version.Version,
		RiskGrade:          RiskGrade(summary.RiskScore),
		CriticalCount:      summary.SeverityCounts[models.SeverityCritical],
		HighCount:          summary.SeverityCounts[models.SeverityHigh],
		MediumCount:        summary.SeverityCounts[models.SeverityMedium],
		LowCount:           summary.SeverityCounts[models.SeverityLow],
		InfoCount:          summary.SeverityCounts[models.SeverityInfo],
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating HTML report file %s: %w", path, err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("rendering HTML report: %w", err)
	}
	return nil
}
