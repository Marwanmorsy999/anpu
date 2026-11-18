package sstiexpand

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
)

func testClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

func testContext(srv string) *scanner.ScanContext {
	u, _ := url.Parse(srv)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	return &scanner.ScanContext{Target: &scanner.ValidatedTarget{Raw: srv, URL: u, Host: host}}
}

// Regression (DVWA ultra validation, 2026-10-18): DVWA's login page embeds
// "49" in static chrome (a DOCTYPE URL). When the control response already
// contains "49", a payload response with the same "49" count must NOT be
// treated as evaluation — the substring appeared before any probing.
func TestStaticChrome49IsNotEvaluation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Static page containing "49" in chrome (mirrors DVWA, whose
		// login page carries "49" in a DOCTYPE-adjacent string), never
		// changes with input.
		_, _ = w.Write([]byte("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0//EN\" " +
			"\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n" +
			"<html><body><span style=\"width:49px\">hi</span></body></html>"))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "sstiexpand-evaluated" {
			t.Fatalf("static-chrome 49 must not raise SSTI, got %q", f.Title)
		}
	}
}

// When the control contains static "49" AND the payload response contains
// strictly more "49"s, the extra one is payload-attributable — still a hit.
func TestChrome49WithPayloadAttributableExtraStillHits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "<!DOCTYPE html><html><body>hi</body></html>"
		if p := r.URL.Query().Get("anpuprobe"); p == "${7*7}" {
			body += "\ncomputed: 49" // server evaluated the expression
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.ID == "sstiexpand-evaluated" && strings.Contains(f.Title, "Tornado/Mako/Jinja") {
			found = true
		}
	}
	if !found {
		t.Fatalf("payload-attributable 49 must raise SSTI, got %d findings", len(res.Findings))
	}
}

// DVWA's login page carries a random 32-hex user_token per response; ~12%
// of tokens contain "49" by chance. Raw body comparison made the finding's
// engine label flip run-to-run (observed: Velocity → Tornado → EJS across
// three DVWA scans). Volatile hex runs must be stripped before comparison.
func TestRandomHexTokenLuck49IsNotEvaluation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("anpuprobe")
		token := "1debfbe2fe79ecd22e201e41019e1d2a" // no "49": control token
		if p != "" && p != "anpu9x8z7" {
			token = "f0e1d2c3b4a59687149aabbccddeeff0" // probe token lucks into "49"
		}
		_, _ = w.Write([]byte("<html><body><input name='user_token' value='" + token + "'></body></html>"))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "sstiexpand-evaluated" {
			t.Fatalf("lucky hex token must not raise SSTI, got %q", f.Title)
		}
	}
}

// A real evaluation must still fire even when both control and payload
// responses carry random tokens (with or without "49" in them).
func TestEvaluationFiresDespiteRandomTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("anpuprobe")
		body := "<html><body><input name='user_token' value='1debfbe2fe79ecd22e201e449019e1d2'>"
		if p == "${7*7}" {
			body += "<div>result: 49</div>"
		}
		_, _ = w.Write([]byte(body + "</body></html>"))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.ID == "sstiexpand-evaluated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("evaluation with random tokens present must still raise SSTI, got %d findings", len(res.Findings))
	}
}

// The control request failing at transport level used to silently disable
// the chrome guard (empty control body → contains("49") false → FP). The
// scanner must fall back to the baseline response for subtraction. DVWA
// under scan load intermittently errored the control request, flipping
// the SSTI finding's engine label run-to-run.
func TestControlTransportErrorFallsBackToBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("anpuprobe") == "anpu9x8z7" {
			// Kill the connection: transport-level error, not a response.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("server does not support hijack")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close() // close error irrelevant: the connection is deliberately killed
			return
		}
		// Static chrome contains "49"; nothing ever evaluates.
		_, _ = w.Write([]byte("<html><body><span style=\"width:49px\">hi</span></body></html>"))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "sstiexpand-evaluated" {
			t.Fatalf("errored control + static chrome must not raise SSTI, got %q", f.Title)
		}
	}
}

// Clean case: control has no "49", payload evaluates to 49 — plain hit.
func TestCleanEvaluationHits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "<html><body>hi</body></html>"
		if p := r.URL.Query().Get("anpuprobe"); p == "${7*7}" {
			body += "\nresult: 49"
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected an SSTI finding")
	}
}

// True positive: a Jinja2-style endpoint that actually evaluates {{7*7}} /
// ${7*7} into 49 (no static "49", no tokens) must be detected by the fixed
// scanner. This is the detection side of the DVWA FP fix: the chrome/token
// subtraction must not swallow a real evaluation.
func TestJinja2TruePositiveDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("anpuprobe")
		body := "<html><body><h1>Hello, guest</h1></body></html>"
		// Local vulnerable-Jinja2 fixture: evaluates both Jinja2 styles.
		if p == "{{7*7}}" || p == "${7*7}" {
			body = "<html><body><h1>Hello, 49</h1></body></html>"
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.ID == "sstiexpand-evaluated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Jinja2 true positive must raise SSTI, got %d findings", len(res.Findings))
	}
}

// Verbatim reflection of the payload is input echo, not evaluation.
func TestEchoGuardStillApplies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("anpuprobe")
		_, _ = w.Write([]byte("<html><body>you sent: " + p + " (49)</body></html>"))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "sstiexpand-evaluated" {
			t.Fatalf("echoed payload must not raise SSTI, got %q", f.Title)
		}
	}
}

// Regression (v0.5.7 P0-3): the control response can be a degraded page
// (WAF block page, short error page) that lacks the static "49" the real
// page always carries. The old single-reference logic (ref = control when
// it arrived) blessed that static "49" as evaluation — a false positive.
// Baseline subtraction mirroring sqli.go must run unconditionally: the
// "49" must be NEW relative to the untouched page, whatever the control
// returned.
func TestControlBlockPageDoesNotBypassBaselineSubtraction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("anpuprobe") == "anpu9x8z7" {
			// WAF block page for the random control: no "49".
			_, _ = w.Write([]byte("<html><body>Request blocked by WAF</body></html>"))
			return
		}
		// The real page always carries a static "49" (version string).
		_, _ = w.Write([]byte("<html><body>nginx 1.49.2 — welcome</body></html>"))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "sstiexpand-evaluated" {
			t.Fatalf("static 49 blessed by a degraded control must not raise SSTI, got %q", f.Title)
		}
	}
}

// The fix must not swallow true positives when the control is degraded:
// a real evaluation gains "49" over BOTH the baseline and the control.
func TestEvalStillFiresWhenControlIsBlockPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("anpuprobe")
		if p == "anpu9x8z7" {
			_, _ = w.Write([]byte("<html><body>Request blocked by WAF</body></html>"))
			return
		}
		body := "<html><body><h1>Hello, guest</h1></body></html>"
		if p == "${7*7}" {
			body = "<html><body><h1>Hello, 49</h1></body></html>"
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.ID == "sstiexpand-evaluated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("real evaluation behind a degraded control must still raise SSTI, got %d findings", len(res.Findings))
	}
}

// Baseline request errored but the control arrived: the baseline term is
// vacuous and the control guard carries the decision. A static "49" page
// must stay silent (payload gains nothing over the control).
func TestBaselineErrorLeavesControlGuardInCharge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "" {
			// Warm-up and baseline requests (no probe param): kill the
			// connection so the baseline comes back empty.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("server does not support hijack")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		// Everything probed lands here: static "49" in both control and
		// payload responses, nothing ever evaluates.
		_, _ = w.Write([]byte("<html><body>build 49 — ok</body></html>"))
	}))
	defer srv.Close()
	res, err := New(testClient()).Run(context.Background(), testContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == "sstiexpand-evaluated" {
			t.Fatalf("errored baseline + static 49 must not raise SSTI, got %q", f.Title)
		}
	}
}
