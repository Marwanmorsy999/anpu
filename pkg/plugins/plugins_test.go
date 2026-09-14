package plugins

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func fakeFetch(bodies map[string]string) FetchFunc {
	return func(_ context.Context, url string) (int, http.Header, []byte, error) {
		for path, body := range bodies {
			if strings.HasSuffix(url, path) {
				return 200, http.Header{"Content-Type": []string{"text/html"}}, []byte(body), nil
			}
		}
		return 404, nil, []byte("not found"), nil
	}
}

const validYAML = `checks:
  - name: generator-meta
    path: /
    match: '<meta\s+name="generator"'
    title: Generator meta tag discloses platform
    description: test description
    severity: low
    confidence: high
    category: technology-disclosure
    remediation: Remove the tag.
`

func TestLoadChecksValid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(p, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	checks, err := LoadChecks(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || checks[0].Name != "generator-meta" {
		t.Fatalf("unexpected checks: %+v", checks)
	}
}

func TestLoadChecksRejects(t *testing.T) {
	cases := map[string]string{
		"missing":  "checks: []\n",
		"no-name":  "checks:\n  - path: /\n    match: x\n    title: t\n    severity: low\n    confidence: high\n    category: other\n",
		"rel-path": "checks:\n  - name: a\n    path: rel\n    match: x\n    title: t\n    severity: low\n    confidence: high\n    category: other\n",
		"bad-re":   "checks:\n  - name: a\n    path: /\n    match: '(['\n    title: t\n    severity: low\n    confidence: high\n    category: other\n",
		"bad-sev":  "checks:\n  - name: a\n    path: /\n    match: x\n    title: t\n    severity: cosmic\n    confidence: high\n    category: other\n",
		"bad-conf": "checks:\n  - name: a\n    path: /\n    match: x\n    title: t\n    severity: low\n    confidence: certain\n    category: other\n",
		"bad-cat":  "checks:\n  - name: a\n    path: /\n    match: x\n    title: t\n    severity: low\n    confidence: high\n    category: everything\n",
		"bad-yaml": "checks: [oops\n",
	}
	for name, content := range cases {
		p := filepath.Join(t.TempDir(), name+".yaml")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadChecks(p); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	if _, err := LoadChecks(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestRunChecksMatchAndMiss(t *testing.T) {
	p := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(p, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	checks, err := LoadChecks(p)
	if err != nil {
		t.Fatal(err)
	}
	hit, err := RunChecks(context.Background(), "https://example.com",
		checks, fakeFetch(map[string]string{"/": `<html><head><meta name="generator" content="X 1.0"></head></html>`}))
	if err != nil || len(hit) != 1 {
		t.Fatalf("expected 1 hit, got %v %v", hit, err)
	}
	f := hit[0]
	if f.Source != models.SourcePlugin || f.URL != "https://example.com/" {
		t.Fatalf("attribution wrong: %+v", f)
	}
	if !strings.HasPrefix(f.ID, "plugin-") {
		t.Fatalf("plugin IDs must be namespaced: %q", f.ID)
	}
	if !strings.Contains(f.Evidence.Observed, "marker matched") {
		t.Fatalf("evidence must cite the match: %+v", f.Evidence)
	}
	// Deterministic IDs across runs.
	hit2, err := RunChecks(context.Background(), "https://example.com",
		checks, fakeFetch(map[string]string{"/": `<meta name="generator" content="Y">`}))
	if err != nil || len(hit2) != 1 || hit2[0].ID != f.ID {
		t.Fatalf("IDs must be stable: %+v %+v", hit, hit2)
	}
	miss, err := RunChecks(context.Background(), "https://example.com",
		checks, fakeFetch(map[string]string{"/": `<html><head></head></html>`}))
	if err != nil || len(miss) != 0 {
		t.Fatalf("no match must yield no findings: %v %v", miss, err)
	}
	notFound, err := RunChecks(context.Background(), "https://example.com",
		checks, fakeFetch(map[string]string{}))
	if err != nil || len(notFound) != 0 {
		t.Fatalf("404 must not match: %v %v", notFound, err)
	}
}

func TestRegistry(t *testing.T) {
	ResetRegistry()
	t.Cleanup(ResetRegistry)
	if len(List()) != 0 {
		t.Fatal("fresh registry must be empty")
	}
	p := &stubPlugin{name: "demo-check"}
	Register(p)
	if got := List(); len(got) != 1 || got[0] != "demo-check" {
		t.Fatalf("list wrong: %v", got)
	}
	found, ok := Lookup("demo-check")
	if !ok || found.Name() != "demo-check" {
		t.Fatal("lookup must find the plugin")
	}
	if _, ok := Lookup("nope"); ok {
		t.Fatal("unknown lookup must fail")
	}
	out, err := RunNamed(context.Background(), "demo-check", "https://example.com", fakeFetch(nil))
	if err != nil || len(out) != 1 {
		t.Fatalf("RunNamed: %v %v", out, err)
	}
	if _, err := RunNamed(context.Background(), "nope", "https://example.com", fakeFetch(nil)); err == nil {
		t.Fatal("RunNamed unknown must error")
	}
}

func TestRegisterPanics(t *testing.T) {
	ResetRegistry()
	t.Cleanup(ResetRegistry)
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate registration must panic")
		}
	}()
	Register(&stubPlugin{name: "dup"})
	Register(&stubPlugin{name: "dup"})
}

type stubPlugin struct{ name string }

func (s *stubPlugin) Name() string        { return s.name }
func (s *stubPlugin) Description() string { return "stub" }
func (s *stubPlugin) Run(_ context.Context, target string, _ FetchFunc) ([]models.Finding, error) {
	return []models.Finding{{ID: "stub-1", Title: "Stub", Target: target, Source: models.SourcePlugin}}, nil
}
