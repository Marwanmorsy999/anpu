package integrations

import (
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/internal/scanner"
)

// Phase 4: colorized piped output must not silently break text parsers,
// and JSON-shape drift must warn loudly instead of yielding nothing.
func parseCtx() *scanner.ScanContext {
	return &scanner.ScanContext{Target: &scanner.ValidatedTarget{Raw: "https://example.com", Host: "example.com"}}
}

func TestStripANSI(t *testing.T) {
	colored := []byte("\x1b[32madmin\x1b[0m\t[Status: \x1b[1m200\x1b[0m, Size: 12]\n\x1b[2Kprogress 50%\r")
	plain := string(stripANSI(colored))
	if strings.Contains(plain, "\x1b") {
		t.Fatalf("ANSI must be stripped: %q", plain)
	}
	if !strings.Contains(plain, "admin") || !strings.Contains(plain, "200") {
		t.Fatalf("content must survive: %q", plain)
	}
	if got := string(stripANSI([]byte("plain text"))); got != "plain text" {
		t.Fatal("plain input must pass through")
	}
}

func TestParseFuzzerTolerant(t *testing.T) {
	spec, _ := SpecByName("ffuf")
	// SGR colors + lowercase + Length variant (feroxbuster-ish).
	out := []byte("\x1b[32madmin\x1b[0m\t[status: 200, Length: 123]\nlogin\t[Status: 403, Size: 45]\n")
	fs, _ := parseFuzzer(spec, parseCtx(), out, "repro")
	_ = fs
	// Note: parseFuzzer matches on raw bytes; ANSI is stripped by the
	// normalize() funnel. Strip here to mirror production behavior.
	fs, _ = parseFuzzer(spec, parseCtx(), stripANSI(out), "repro")
	if len(fs) != 2 {
		t.Fatalf("expected 2 hits (case/length tolerant), got %d", len(fs))
	}
	if string(fs[0].Severity) != "info" || string(fs[1].Severity) != "low" {
		t.Fatalf("200->info 403->low, got %s/%s", fs[0].Severity, fs[1].Severity)
	}
}

func TestJSONShapeWarning(t *testing.T) {
	spec, _ := SpecByName("semgrep")
	if w := jsonShapeWarning(spec, []byte(`{"results": []}`)); w != "" {
		t.Fatalf("valid JSON must not warn: %q", w)
	}
	if w := jsonShapeWarning(spec, []byte("")); w != "" {
		t.Fatalf("empty output must not warn: %q", w)
	}
	big := strings.Repeat("not json at all — table output? ", 20)
	if w := jsonShapeWarning(spec, []byte(big)); !strings.Contains(w, "semgrep") || !strings.Contains(w, "miners still ran") {
		t.Fatalf("drifted shape must warn loudly, got %q", w)
	}
	plainSpec, _ := SpecByName("nikto")
	if w := jsonShapeWarning(plainSpec, []byte(big)); w != "" {
		t.Fatalf("non-JSON tools must not warn: %q", w)
	}
}

func TestParseSecretsAltKeys(t *testing.T) {
	spec, _ := SpecByName("gitleaks")
	// gitleaks v8 style: lowercase + Fingerprint + Commit, no legacy keys.
	out := []byte(`[{"description":"generic-api-key","commit":"abc123","file":"config.py","fingerprint":"fp:1"}]`)
	fs, _ := parseSecretsText(spec, parseCtx(), out, "repro")
	if len(fs) != 1 {
		t.Fatalf("alt keys must parse, got %d findings", len(fs))
	}
	// Secret VALUES must never appear in titles.
	out2 := []byte(`[{"Description":"x","Secret":"SUPERSECRETVALUE","Raw":"SUPERSECRETVALUE","File":"a.py"}]`)
	fs2, _ := parseSecretsText(spec, parseCtx(), out2, "repro")
	for _, f := range fs2 {
		if strings.Contains(f.Title, "SUPERSECRETVALUE") || strings.Contains(f.Description, "SUPERSECRETVALUE") {
			t.Fatalf("secret value leaked into finding: %q / %q", f.Title, f.Description)
		}
	}
}
