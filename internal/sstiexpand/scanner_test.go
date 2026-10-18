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
			conn.Close()
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
