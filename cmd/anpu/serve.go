package main

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Marwanmorsy999/anpu/internal/diff"
	"github.com/Marwanmorsy999/anpu/internal/storage"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func newServeCmd() *cobra.Command {
	var addr, dbPath string
	var limit int
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Browse scan history in a local read-only dashboard",
		Long: `serve exposes the SQLite scan history as a read-only local web
dashboard: scan list, per-scan findings with evidence, and scan diffs.

Localhost-only by design: --addr must resolve to loopback (127.0.0.0/8,
::1, or localhost); anything else is refused. Only GET routes exist —
the dashboard can never modify history. For remote access, use an SSH
tunnel instead of exposing the port.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return fmt.Errorf("invalid --addr %q (want host:port): %w", addr, err)
			}
			if !serveLoopbackHost(host) {
				return fmt.Errorf("refusing non-loopback --addr %q: serve is localhost-only (use an SSH tunnel for remote access)", addr)
			}
			if port == "0" || port == "" {
				return fmt.Errorf("invalid --addr %q: refusing port %q", addr, port)
			}
			db := dbPath
			if db == "" {
				db = defaultDBPath()
			}
			store, err := storage.Open(db)
			if err != nil {
				return fmt.Errorf("opening scan history database: %w", err)
			}
			defer func() { _ = store.Close() }()
			srv := &http.Server{
				Addr:              addr,
				Handler:           newServeMux(store, limit),
				ReadHeaderTimeout: 5 * time.Second,
			}
			_, _ = fmt.Fprintf(os.Stderr, "anpu serve: read-only dashboard at http://%s (Ctrl+C to stop)\n", addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "listen address, loopback only (host:port)")
	cmd.Flags().StringVar(&dbPath, "db", "", "history database path (default ~/.anpu/anpu.db)")
	cmd.Flags().IntVar(&limit, "limit", 50, "max scans on the index page")
	return cmd
}

// serveLoopbackHost reports whether host is loopback. Only literal
// loopback IPs and "localhost" qualify — anything else (LAN IPs,
// hostnames, empty) is refused so serve can never bind outward.
func serveLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

var serveTemplates = template.Must(template.New("serve").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>{{.Title}} — anpu serve</title>
<style>body{font-family:system-ui,sans-serif;max-width:1000px;margin:2em auto;padding:0 1em;color:#222}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.4em;text-align:left;font-size:.9em}
th{background:#f4f4f4}code{font-size:.85em}.muted{color:#666}nav{margin-bottom:1em}</style>
</head><body><nav><a href="/">scans</a> <span class="muted">· read-only · localhost-only</span></nav>
<h1>{{.Title}}</h1>{{.Body}}</body></html>`))

type servePage struct {
	Title string
	Body  template.HTML
}

// newServeMux builds the read-only dashboard routes. GET only: any
// other method gets 405, so history cannot be modified over HTTP.
func newServeMux(store *storage.Store, pageLimit int) *http.ServeMux {
	if pageLimit <= 0 {
		pageLimit = 50
	}
	mux := http.NewServeMux()
	getOnly := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "read-only dashboard: GET only", http.StatusMethodNotAllowed)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/", getOnly(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		scans, err := store.ListScans(pageLimit)
		if err != nil {
			http.Error(w, "listing scans: "+err.Error(), http.StatusInternalServerError)
			return
		}
		var b strings.Builder
		if len(scans) == 0 {
			b.WriteString("<p>No scans in history yet. Run <code>anpu scan</code> first.</p>")
		} else {
			b.WriteString("<table><tr><th>Scan</th><th>Target</th><th>Profile</th><th>Started</th><th>Status</th><th>Risk</th><th>Findings</th><th></th></tr>")
			for _, s := range scans {
				fmt.Fprintf(&b, "<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.1f</td><td>%d</td><td><a href=\"/scan?id=%s\">open</a></td></tr>",
					template.HTMLEscapeString(s.ID), template.HTMLEscapeString(s.Target), template.HTMLEscapeString(string(s.Profile)),
					template.HTMLEscapeString(s.StartedAt), template.HTMLEscapeString(s.Status), s.RiskScore, s.FindingsCnt,
					template.HTMLEscapeString(urlQueryEscape(s.ID)))
			}
			b.WriteString("</table>")
			b.WriteString(`<p class="muted">Compare two scans: <code>/diff?from=&lt;id&gt;&amp;to=&lt;id&gt;</code></p>`)
		}
		renderServePage(w, "Scans", b.String())
	}))
	mux.HandleFunc("/scan", getOnly(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing ?id=", http.StatusBadRequest)
			return
		}
		sum, err := store.GetScan(id)
		if err != nil {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		var b strings.Builder
		fmt.Fprintf(&b, "<p>Target <code>%s</code> · profile <code>%s</code> · risk <strong>%.1f</strong> · %d findings</p>",
			template.HTMLEscapeString(sum.Target), template.HTMLEscapeString(string(sum.Profile)), sum.RiskScore, len(sum.Findings))
		b.WriteString("<table><tr><th>Severity</th><th>Confidence</th><th>Title</th><th>URL</th><th></th></tr>")
		for _, f := range sum.Findings {
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td><a href=\"/finding?scan=%s&finding=%s\">evidence</a></td></tr>",
				template.HTMLEscapeString(string(f.Severity)), template.HTMLEscapeString(string(f.Confidence)),
				template.HTMLEscapeString(f.Title), template.HTMLEscapeString(f.URL),
				template.HTMLEscapeString(urlQueryEscape(sum.ID)), template.HTMLEscapeString(urlQueryEscape(f.ID)))
		}
		b.WriteString("</table>")
		renderServePage(w, "Scan "+shortID(sum.ID), b.String())
	}))
	mux.HandleFunc("/finding", getOnly(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		sum, err := store.GetScan(q.Get("scan"))
		if err != nil {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		var found *models.Finding
		for i := range sum.Findings {
			if sum.Findings[i].ID == q.Get("finding") {
				found = &sum.Findings[i]
				break
			}
		}
		if found == nil {
			http.Error(w, "finding not found in scan", http.StatusNotFound)
			return
		}
		f := found
		var b strings.Builder
		row := func(k, v string) {
			fmt.Fprintf(&b, "<p><strong>%s:</strong> %s</p>", k, template.HTMLEscapeString(v))
		}
		row("Title", f.Title)
		row("Severity / confidence", string(f.Severity)+" / "+string(f.Confidence))
		row("Category", string(f.Category))
		row("URL", f.URL)
		row("Source", string(f.Source))
		row("Detection", f.DetectionMethod)
		row("Description", f.Description)
		row("Evidence", f.Evidence.Observed+" ["+f.Evidence.Location+"]")
		row("Score", fmt.Sprintf("%.1f — %s", f.RiskScore, f.ScoreExplanation))
		if f.Remediation != "" {
			row("Remediation", f.Remediation)
		}
		if len(f.MergedFrom) > 0 {
			var srcs []string
			for _, ref := range f.MergedFrom {
				srcs = append(srcs, string(ref.Source))
			}
			row("Merged sources", strings.Join(srcs, ", "))
		}
		renderServePage(w, "Finding "+shortID(f.ID), b.String())
	}))
	mux.HandleFunc("/diff", getOnly(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		before, err1 := store.GetScan(q.Get("from"))
		after, err2 := store.GetScan(q.Get("to"))
		if err1 != nil || err2 != nil {
			http.Error(w, "both ?from= and ?to= must be known scan IDs", http.StatusNotFound)
			return
		}
		res := diff.Compare(before, after)
		var b strings.Builder
		fmt.Fprintf(&b, "<p>Risk %.1f → %.1f (Δ %+.1f) · +%d/−%d/~%d findings · +%d/−%d endpoints</p>",
			res.RiskBefore, res.RiskAfter, res.RiskDelta,
			res.FindingsAdded, res.FindingsRemoved, res.FindingsChanged,
			res.EndpointsAdded, res.EndpointsRemoved)
		for _, fc := range res.Findings {
			fmt.Fprintf(&b, "<p><strong>%s</strong> [%s] %s</p>", template.HTMLEscapeString(fc.Kind),
				template.HTMLEscapeString(string(fc.Finding.Severity)), template.HTMLEscapeString(fc.Finding.Title))
		}
		renderServePage(w, "Diff "+shortID(res.FromID)+" → "+shortID(res.ToID), b.String())
	}))
	return mux
}

func renderServePage(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Body is pre-rendered markup: every untrusted value interpolated
	// into it MUST pass through template.HTMLEscapeString (or
	// url.QueryEscape for URLs) at the call site. html/template still
	// escapes Title.
	_ = serveTemplates.Execute(w, servePage{Title: title, Body: template.HTML(body)}) // #nosec G203 -- body values are escaped at construction (see above); template.HTML carries pre-rendered markup only.
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}
