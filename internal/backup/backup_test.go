package backup

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func backupClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

func backupContext(srv string) *scanner.ScanContext {
	u, _ := url.Parse(srv)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	return &scanner.ScanContext{Target: &scanner.ValidatedTarget{Raw: srv, URL: u, Host: host}}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return string(data)
}

// Phase 2: an SPA catch-all (same shell for every path) must produce
// zero backup findings — the root template suppresses them.
func TestBackupCatchAllShellSuppressed(t *testing.T) {
	shell := readFixture(t, "soft404-baseline-a.html")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(shell))
	}))
	defer srv.Close()
	res, err := New(backupClient()).Run(context.Background(), backupContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("catch-all shell must yield 0 findings, got %d (%v)", len(res.Findings), res.Findings[0].Title)
	}
}

// Phase 2: WAF block pages served as 200 must not become exposures.
func TestBackupWAFBlockSuppressed(t *testing.T) {
	block := readFixture(t, "waf-block.html")
	// Pad past minBodyBytes so the veto (not the size gate) is exercised.
	for len(block) < 300 {
		block += "<!-- padding to exceed trivial-size gate -->"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(block))
	}))
	defer srv.Close()
	res, err := New(backupClient()).Run(context.Background(), backupContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("WAF block must yield 0 findings, got %d", len(res.Findings))
	}
}

// Sanity-pass follow-up: /backup.zip is the most obvious archive name
// and must be probed.
func TestRootBackupPathsIncludeBackupZip(t *testing.T) {
	found := false
	for _, rb := range rootBackupPaths {
		if rb.path == "/backup.zip" {
			found = true
		}
	}
	if !found {
		t.Fatal("rootBackupPaths must include /backup.zip")
	}
}

// Budget: endpoint-rich targets must not fan out unbounded — probes are
// capped and stored findings stop at maxFindings once exposure is proven.
func TestBackupProbeBudgetCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<html><head><title>Home</title></head><body>welcome</body></html>"))
			return
		}
		// Every backup candidate looks exposed: distinct body per path so
		// the soft-404 baseline never matches.
		w.Header().Set("Content-Type", "text/plain")
		body := fmt.Sprintf("<?php // backup of %s\n$secret = 'x';\n", r.URL.Path) + strings.Repeat("x", 300)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	ctx := backupContext(srv.URL)
	for i := 0; i < 20; i++ {
		ctx.Endpoints = append(ctx.Endpoints, models.Endpoint{URL: fmt.Sprintf("%s/page%d.php", srv.URL, i)})
	}
	ctx.Verbose = true
	res, err := New(backupClient()).Run(context.Background(), ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) > maxFindings {
		t.Fatalf("findings must cap at %d, got %d", maxFindings, len(res.Findings))
	}
	for _, wmsg := range res.Warnings {
		var probed, found int
		if _, err := fmt.Sscanf(wmsg, "backup-scanner: probed %d candidate backup paths, found %d exposed files", &probed, &found); err == nil {
			if probed > maxProbes {
				t.Fatalf("probes must cap at %d, got %d", maxProbes, probed)
			}
		}
	}
}

// A genuinely distinct backup file must still be found (no over-suppression).
func TestBackupRealFileStillFound(t *testing.T) {
	const dump = "-- MySQL dump 10.13\n-- Host: localhost\nCREATE TABLE users (id INT PRIMARY KEY, pw VARCHAR(255));\nINSERT INTO users VALUES (1,'hash');\n" +
		"-- MySQL dump 10.13\n-- Host: localhost\nCREATE TABLE users (id INT PRIMARY KEY, pw VARCHAR(255));\nINSERT INTO users VALUES (1,'hash');\n" +
		"-- MySQL dump 10.13\n-- Host: localhost\nCREATE TABLE users (id INT PRIMARY KEY, pw VARCHAR(255));\nINSERT INTO users VALUES (1,'hash');\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<html><head><title>Home</title></head><body>welcome</body></html>"))
			return
		}
		if strings.HasSuffix(r.URL.Path, ".sql") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(dump))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()
	res, err := New(backupClient()).Run(context.Background(), backupContext(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("real .sql dump must be found")
	}
}
