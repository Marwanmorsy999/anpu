package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func verifyClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

func TestVerifyBackupConfirmedRejected(t *testing.T) {
	ctx := context.Background()
	exposed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("<?php $secret='x';\n" + strings.Repeat("x", 300)))
	}))
	defer exposed.Close()
	if ev, v := verifyBackupURL(ctx, verifyClient(), exposed.URL+"/config.php.bak"); v != "CONFIRMED" {
		t.Fatalf("served backup must CONFIRM, got %s (%s)", v, ev)
	}
	gone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer gone.Close()
	if _, v := verifyBackupURL(ctx, verifyClient(), gone.URL+"/config.php.bak"); v != "REJECTED" {
		t.Fatalf("missing file must REJECT, got %s", v)
	}
}

func TestVerifyPostureConfirmedRejected(t *testing.T) {
	ctx := context.Background()
	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>hi</body></html>"))
	}))
	defer bare.Close()
	ev, v := verifyPosture(ctx, verifyClient(), bare.URL)
	if v != "CONFIRMED" || !strings.Contains(ev, "Content-Security-Policy") {
		t.Fatalf("bare server must CONFIRM posture, got %s (%s)", v, ev)
	}
	full := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Permissions-Policy", "camera=()")
		h.Set("Referrer-Policy", "no-referrer")
		_, _ = w.Write([]byte("<html><body>hi</body></html>"))
	}))
	defer full.Close()
	if ev, v := verifyPosture(ctx, verifyClient(), full.URL); v != "REJECTED" {
		t.Fatalf("hardened server must REJECT posture, got %s (%s)", v, ev)
	}
}

func TestVerifyNoSQLInvalidTargetInconclusive(t *testing.T) {
	f := models.Finding{ID: "nosqlexpand-differential", Title: "NoSQL injection differential", Target: "http://127.0.0.1/"}
	if _, v := verifyNoSQL(context.Background(), verifyClient(), f); v != "INCONCLUSIVE" {
		t.Fatalf("loopback target must be INCONCLUSIVE under default guards, got %s", v)
	}
}

func TestVerifyUnknownDetectorInconclusive(t *testing.T) {
	f := models.Finding{ID: "mystery-1", Title: "Something", Target: "https://example.com"}
	v := verifyFinding(context.Background(), f)
	if v.Verdict != "INCONCLUSIVE" {
		t.Fatalf("unknown detector must be INCONCLUSIVE, got %s", v.Verdict)
	}
}
