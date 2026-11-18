package integrations

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Digest record-then-verify tests (v0.5.7 P0-4). These tests are keyed on
// the POSIX HOME env var (os.UserHomeDir on Windows ignores HOME), so
// they skip on non-POSIX hosts; the digest machinery itself is
// platform-neutral.
func requirePOSIXHome(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("HOME-based digest state tests need a POSIX os.UserHomeDir")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOPATH", "")        // candidate list determinism
	t.Setenv("GOBIN", "")         // candidate list determinism
	t.Setenv("PATH", t.TempDir()) // keep the host's real binaries out of LookPath
}

// fakeTool writes an executable-shaped file named after the registry
// binary into dir and returns its path.
func fakeTool(t *testing.T, dir, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil { // #nosec G306 -- fake executable fixture
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestRecordedDigestVerifies(t *testing.T) {
	requirePOSIXHome(t)
	gobin := t.TempDir()
	t.Setenv("GOBIN", gobin)
	fakeTool(t, gobin, "assetfinder", "#!/bin/sh\necho assetfinder test\n")

	if err := RecordInstalledDigest("assetfinder", "v0.1.1", "go"); err != nil {
		t.Fatalf("RecordInstalledDigest: %v", err)
	}
	sum, ok := RecordedDigest("assetfinder")
	if !ok || len(sum) != 64 {
		t.Fatalf("recorded digest missing or malformed: %q ok=%v", sum, ok)
	}
	// findExecutable must still resolve it — nothing drifted.
	path, ok := LookupBinary("assetfinder")
	if !ok {
		t.Fatalf("recorded binary refused without drift")
	}
	if !strings.HasSuffix(path, "assetfinder") {
		t.Fatalf("resolved wrong path %q", path)
	}
	// And the verify report must say ok.
	for _, r := range VerifyAllDigests() {
		if r.Tool == "assetfinder" && r.Status != "ok" {
			t.Fatalf("verify status = %s (%s), want ok", r.Status, r.Detail)
		}
	}
}

// The core fail-closed guarantee: a binary that changed since install is
// refused at resolution time — every wrapper inherits the refusal.
func TestDriftedBinaryRefusedAtRunTime(t *testing.T) {
	requirePOSIXHome(t)
	gobin := t.TempDir()
	t.Setenv("GOBIN", gobin)
	path := fakeTool(t, gobin, "assetfinder", "#!/bin/sh\necho benign\n")

	if err := RecordInstalledDigest("assetfinder", "v0.1.1", "go"); err != nil {
		t.Fatalf("RecordInstalledDigest: %v", err)
	}

	// Tamper: rewrite the "binary" (different size → fresh cache key).
	if err := os.WriteFile(path, []byte("#!/bin/sh\nrm -rf ~ # tampered\n"), 0o755); err != nil { // #nosec G306 -- fake executable fixture
		t.Fatalf("tamper write: %v", err)
	}

	_, ok := LookupBinary("assetfinder")
	if ok {
		t.Fatal("drifted binary must be refused, but it resolved")
	}
	if err, refused := digestDriftAt("assetfinder", path); !refused || err == nil {
		t.Fatalf("expected a refusal error, got refused=%v err=%v", refused, err)
	} else if !strings.Contains(err.Error(), "refusing to execute a modified tool binary") {
		t.Fatalf("refusal must name the failure, got: %v", err)
	}
}

// No record (installed outside anpu, or state deleted) must NOT be
// refused at run time — that would break every operator who installed
// tools manually before the digest baseline existed. verify flags those
// as norecord instead.
func TestUnrecordedBinaryStillResolves(t *testing.T) {
	requirePOSIXHome(t)
	gobin := t.TempDir()
	t.Setenv("GOBIN", gobin)
	fakeTool(t, gobin, "assetfinder", "#!/bin/sh\necho x\n")

	if _, ok := RecordedDigest("assetfinder"); ok {
		t.Fatal("no record should exist yet")
	}
	if _, ok := LookupBinary("assetfinder"); !ok {
		t.Fatal("unrecorded binary must still resolve")
	}
	// verify must surface it for baselining, not silently pass it.
	for _, r := range VerifyAllDigests() {
		if r.Tool == "assetfinder" && r.Status != "norecord" {
			t.Fatalf("verify status = %s, want norecord", r.Status)
		}
	}
}

// A corrupt trust anchor must not silently disable the digest check: the
// refusal (fail closed) wins over availability.
func TestCorruptDigestStateRefusesExecution(t *testing.T) {
	requirePOSIXHome(t)
	gobin := t.TempDir()
	t.Setenv("GOBIN", gobin)
	path := fakeTool(t, gobin, "assetfinder", "#!/bin/sh\necho x\n")

	if err := RecordInstalledDigest("assetfinder", "v0.1.1", "go"); err != nil {
		t.Fatalf("RecordInstalledDigest: %v", err)
	}
	statePath, err := DigestStatePath()
	if err != nil {
		t.Fatalf("DigestStatePath: %v", err)
	}
	if err := os.WriteFile(statePath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt state write: %v", err)
	}

	_, ok := LookupBinary("assetfinder")
	if ok {
		t.Fatal("corrupt digest state must refuse execution, not fall back to trusting the binary")
	}
	if err, refused := digestDriftAt("assetfinder", path); !refused || err == nil || !strings.Contains(err.Error(), "digest state unreadable") {
		t.Fatalf("expected digest-state refusal, got refused=%v err=%v", refused, err)
	}
}

// State file permissions: the record is the trust anchor, so it must not
// be world-writable.
func TestDigestStatePermissions(t *testing.T) {
	requirePOSIXHome(t)
	gobin := t.TempDir()
	t.Setenv("GOBIN", gobin)
	fakeTool(t, gobin, "assetfinder", "#!/bin/sh\necho x\n")

	if err := RecordInstalledDigest("assetfinder", "v0.1.1", "go"); err != nil {
		t.Fatalf("RecordInstalledDigest: %v", err)
	}
	statePath, err := DigestStatePath()
	if err != nil {
		t.Fatalf("DigestStatePath: %v", err)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("state file mode = %o, want 600", perm)
	}
}
