package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Marwanmorsy999/anpu/internal/storage"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func seedServeStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "serve.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	mk := func(id, target string, score float64) *models.ScanSummary {
		return &models.ScanSummary{
			ID: id, Target: target, Profile: models.ProfileSafe,
			StartedAt: time.Now().Add(-time.Hour), CompletedAt: time.Now(),
			Status: "completed", RiskScore: score,
			Findings: []models.Finding{{
				ID: "f-" + id, Title: "Posture <b>check</b>", Severity: models.SeverityLow,
				Confidence: models.ConfidenceHigh, Category: models.CategoryHeaders,
				URL: target, Source: models.SourceHeaders, DetectionMethod: "passive",
				Evidence:  models.Evidence{Observed: "CSP: <absent>", Location: "headers"},
				RiskScore: 1.1, ScoreExplanation: "base=2.0",
			}},
		}
	}
	if err := store.SaveScan(mk("scan-aaa", "https://a.example", 1.1)); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveScan(mk("scan-bbb", "https://b.example", 2.2)); err != nil {
		t.Fatal(err)
	}
	return store
}

func serveGet(t *testing.T, mux *http.ServeMux, method, target string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestServeIndexListsScans(t *testing.T) {
	mux := newServeMux(seedServeStore(t), 50)
	code, body := serveGet(t, mux, "GET", "/")
	if code != http.StatusOK {
		t.Fatalf("index status %d", code)
	}
	for _, want := range []string{"scan-aaa", "scan-bbb", "https://a.example"} {
		if !strings.Contains(body, want) {
			t.Fatalf("index must list %q", want)
		}
	}
}

func TestServeIndexEmpty(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	_, body := serveGet(t, newServeMux(store, 50), "GET", "/")
	if !strings.Contains(body, "No scans") {
		t.Fatalf("empty history must hint at scanning:\n%s", body)
	}
}

func TestServeScanAndFinding(t *testing.T) {
	mux := newServeMux(seedServeStore(t), 50)
	code, body := serveGet(t, mux, "GET", "/scan?id=scan-aaa")
	if code != http.StatusOK || !strings.Contains(body, "Posture") {
		t.Fatalf("scan page %d must show findings:\n%s", code, body)
	}
	// Titles are HTML-escaped, never raw.
	if strings.Contains(body, "<b>check</b>") {
		t.Fatal("finding titles must be escaped")
	}
	code, _ = serveGet(t, mux, "GET", "/scan")
	if code != http.StatusBadRequest {
		t.Fatalf("missing id must be 400, got %d", code)
	}
	code, _ = serveGet(t, mux, "GET", "/scan?id=nope")
	if code != http.StatusNotFound {
		t.Fatalf("unknown scan must be 404, got %d", code)
	}
	code, body = serveGet(t, mux, "GET", "/finding?scan=scan-aaa&finding=f-scan-aaa")
	if code != http.StatusOK || !strings.Contains(body, "CSP:") || !strings.Contains(body, "base=2.0") {
		t.Fatalf("finding page %d must show evidence and score:\n%s", code, body)
	}
	code, _ = serveGet(t, mux, "GET", "/finding?scan=scan-aaa&finding=nope")
	if code != http.StatusNotFound {
		t.Fatalf("unknown finding must be 404, got %d", code)
	}
}

func TestServeDiff(t *testing.T) {
	mux := newServeMux(seedServeStore(t), 50)
	code, body := serveGet(t, mux, "GET", "/diff?from=scan-aaa&to=scan-bbb")
	if code != http.StatusOK || !strings.Contains(body, "Risk") {
		t.Fatalf("diff page %d must render:\n%s", code, body)
	}
	code, _ = serveGet(t, mux, "GET", "/diff?from=scan-aaa&to=nope")
	if code != http.StatusNotFound {
		t.Fatalf("unknown diff endpoint must be 404, got %d", code)
	}
}

func TestServeReadOnly(t *testing.T) {
	mux := newServeMux(seedServeStore(t), 50)
	for _, tc := range []struct{ method, target string }{
		{"POST", "/"}, {"PUT", "/scan?id=scan-aaa"}, {"DELETE", "/diff?from=a&to=b"}, {"PATCH", "/finding?scan=a&finding=b"},
	} {
		if code, _ := serveGet(t, mux, tc.method, tc.target); code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s must be 405, got %d", tc.method, tc.target, code)
		}
	}
	if code, _ := serveGet(t, mux, "GET", "/nope"); code != http.StatusNotFound {
		t.Fatalf("unknown path must be 404, got %d", code)
	}
}

func TestServeLoopbackHost(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "127.0.0.5", "::1", "localhost"} {
		if !serveLoopbackHost(h) {
			t.Fatalf("%s must be loopback", h)
		}
	}
	for _, h := range []string{"", "0.0.0.0", "::", "192.168.1.1", "10.0.0.1", "example.com", "anpu.local"} {
		if serveLoopbackHost(h) {
			t.Fatalf("%s must be refused", h)
		}
	}
}

func TestServeCmdRegistered(t *testing.T) {
	root := newRootCmd()
	for _, c := range root.Commands() {
		if c.Name() == "serve" {
			if c.GroupID != "results" {
				t.Fatalf("serve must be in results group, got %q", c.GroupID)
			}
			return
		}
	}
	t.Fatal("serve command not registered")
}
