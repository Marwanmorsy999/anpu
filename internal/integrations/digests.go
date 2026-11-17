// Package integrations — digests.go: record-then-verify integrity for
// installed tool binaries (v0.5.7 P0-4, "own-tool rigor").
//
// go/pipx installs are BUILT locally, so no static digest can be shipped
// for them (build output varies by toolchain and platform); what pins
// their content is the version pin plus the Go checksum database / PyPI.
// What can be verified locally is that the binary on disk today is the
// same one the successful install produced:
//
//   - `anpu tools install` records the binary's full sha256 at install
//     time (~/.anpu/tool-digests.json, mode 0600).
//   - every later binary resolution re-hashes the file and REFUSES to
//     execute anything that no longer matches the recorded digest —
//     fail closed: a tampered or silently-modified tool binary is never
//     run, it degrades to a warning with explicit remediation.
//   - `anpu tools verify` is the manual audit entry point: it re-hashes
//     every recorded tool and reports ok / drift / missing.
//
// Docker installs are verified differently and do not appear here: their
// pull ref is digest-addressed (see digestPins), so the registry itself
// rejects any image whose manifest does not hash to the pinned value.
package integrations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// digestRecord is one installed binary's install-time fingerprint.
type digestRecord struct {
	// Digest is the full sha256 hex of the binary file at install time.
	Digest string `json:"digest"`
	// Version is the recipe pin the install used ("" when unpinned).
	Version string `json:"version,omitempty"`
	// Method is the install method (go, pipx, apt, choco).
	Method string `json:"method,omitempty"`
	// Size and ModTime make drift cheap to diagnose without re-hashing.
	Size       int64  `json:"size,omitempty"`
	ModTime    string `json:"mtime,omitempty"`
	RecordedAt string `json:"recorded_at"`
}

// digestState maps binary name → record. Keyed by binary (not tool) name
// because findExecutable only sees the binary name.
type digestState map[string]digestRecord

// DigestStatePath returns the per-user digest state file
// ($HOME/.anpu/tool-digests.json). Exported for the verify command and tests.
func DigestStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home dir: %w", err)
	}
	return filepath.Join(home, ".anpu", "tool-digests.json"), nil
}

// loadDigestState reads the state file. Missing file → empty state, nil
// error (nothing recorded yet is the normal first-run state). A corrupt
// file is an error so verify can surface it instead of silently treating
// every binary as unrecorded.
func loadDigestState() (digestState, error) {
	path, err := DigestStatePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- per-user state path derived from os.UserHomeDir
	if err != nil {
		if os.IsNotExist(err) {
			return digestState{}, nil
		}
		return nil, err
	}
	var st digestState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("corrupt digest state %s: %w (delete it and reinstall tools to re-record)", path, err)
	}
	return st, nil
}

// saveDigestState writes the state file with restrictive permissions
// (0700 dir, 0600 file): it is the trust anchor for run-time refusals.
func saveDigestState(st digestState) error {
	path, err := DigestStatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { // #nosec G301 -- trust-anchor state, operator-private
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600) // #nosec G306 -- trust-anchor state, operator-private
}

// RecordInstalledDigest hashes the resolved binary at install time and
// stores the record. binary is the registry Binary name; the path is
// resolved via the same lookup every run-time caller uses.
func RecordInstalledDigest(binary, version, method string) error {
	path, ok := LookupBinary(binary)
	if !ok {
		return fmt.Errorf("binary %s not found to record", binary)
	}
	sum, size, err := sha256FileFull(path)
	if err != nil {
		return fmt.Errorf("hashing %s: %w", path, err)
	}
	st, err := loadDigestState()
	if err != nil {
		return err
	}
	rec := digestRecord{
		Digest:     sum,
		Version:    version,
		Method:     method,
		Size:       size,
		RecordedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if info, serr := os.Stat(path); serr == nil {
		rec.ModTime = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	}
	st[binary] = rec
	return saveDigestState(st)
}

// RecordedDigest returns the recorded digest for a binary, if any.
func RecordedDigest(binary string) (string, bool) {
	st, err := loadDigestState()
	if err != nil {
		return "", false
	}
	rec, ok := st[binary]
	return rec.Digest, ok && rec.Digest != ""
}

// sha256FileFull hashes a file, streaming (tools can be >100MB), and
// reports the file size.
func sha256FileFull(path string) (string, int64, error) {
	f, err := os.Open(path) // #nosec G304 -- path resolved by findExecutable from the operator's own tool install
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0, err
	}
	info, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), info.Size(), nil
}

// DigestReport is one tool's verify result for `anpu tools verify`.
type DigestReport struct {
	// Tool is the registry tool name.
	Tool string
	// Binary is the resolved executable name.
	Binary string
	// Path is where the binary resolved ("" when missing).
	Path string
	// Status is one of: ok, drift, norecord, missing, error.
	Status string
	// Detail carries the human-readable explanation (digests abbreviated).
	Detail string
}

// VerifyAllDigests audits every registry tool that resolves on this host:
// recorded digests are re-hashed and compared (fail closed report for
// drift), unrecorded-but-installed tools are flagged norecord so the
// operator can re-install through anpu to establish a baseline.
func VerifyAllDigests() []DigestReport {
	var out []DigestReport
	for _, r := range All() {
		path, ok := LookupBinary(r.Binary)
		if !ok {
			out = append(out, DigestReport{Tool: r.Name, Binary: r.Binary, Status: "missing", Detail: "not installed"})
			continue
		}
		st, err := loadDigestState()
		if err != nil {
			out = append(out, DigestReport{Tool: r.Name, Binary: r.Binary, Path: path, Status: "error", Detail: err.Error()})
			continue
		}
		rec, recorded := st[r.Binary]
		if !recorded || rec.Digest == "" {
			out = append(out, DigestReport{Tool: r.Name, Binary: r.Binary, Path: path, Status: "norecord",
				Detail: "installed outside `anpu tools install` (or state deleted) — no baseline to verify against"})
			continue
		}
		sum, _, err := sha256FileFull(path)
		if err != nil {
			out = append(out, DigestReport{Tool: r.Name, Binary: r.Binary, Path: path, Status: "error", Detail: err.Error()})
			continue
		}
		if sum != rec.Digest {
			out = append(out, DigestReport{Tool: r.Name, Binary: r.Binary, Path: path, Status: "drift",
				Detail: fmt.Sprintf("sha256 changed since install (want %s…, got %s…)", rec.Digest[:12], sum[:12])})
			continue
		}
		out = append(out, DigestReport{Tool: r.Name, Binary: r.Binary, Path: path, Status: "ok",
			Detail: "matches install-time record (" + abbrevDigest(sum) + ")"})
	}
	return out
}

func abbrevDigest(sum string) string {
	if len(sum) > 12 {
		return sum[:12] + "…"
	}
	return sum
}

// digestVerdictCache caches per-(path,size,mtime) verdicts so repeated
// findExecutable calls in one scan don't re-hash large binaries. Cleared
// never — entries are content-keyed by stat fingerprint, so a modified
// file produces a new key.
var digestVerdictCache sync.Map

type verdictKey struct {
	path  string
	size  int64
	mtime int64
}

// digestDriftAt returns an error when the file at path differs from the
// recorded install-time digest for binary. Returns (nil, nil) when no
// record exists (unrecorded binaries are not refused here — verify flags
// them for baselining).
func digestDriftAt(binary, path string) (error, bool) {
	st, err := loadDigestState()
	if err != nil {
		// A corrupt trust anchor must not silently disable the check.
		return fmt.Errorf("digest state unreadable (%v) — refusing to execute %s; run `anpu tools verify`", err, binary), true
	}
	rec, recorded := st[binary]
	if !recorded || rec.Digest == "" {
		return nil, false
	}

	info, statErr := os.Stat(path)
	if statErr != nil {
		return statErr, true
	}
	key := verdictKey{path: path, size: info.Size(), mtime: info.ModTime().UnixNano()}
	if v, ok := digestVerdictCache.Load(key); ok {
		if err, refused := v.(error); refused {
			return err, true
		}
		return nil, false // cached ok (nil error, false refused)
	}

	sum, _, err := sha256FileFull(path)
	if err != nil {
		digestVerdictCache.Store(key, err)
		return err, true
	}
	if sum != rec.Digest {
		drift := fmt.Errorf(
			"%s at %s changed since it was installed (sha256 %s…, recorded %s…) — refusing to execute a modified tool binary; audit with `anpu tools verify`, then reinstall via `anpu tools install %s --force` to re-baseline",
			binary, path, abbrevDigest(sum), abbrevDigest(rec.Digest), binary)
		digestVerdictCache.Store(key, drift)
		return drift, true
	}
	digestVerdictCache.Store(key, struct{}{})
	return nil, false
}
