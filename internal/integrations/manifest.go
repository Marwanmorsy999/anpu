// Package integrations — manifest.go: tamper-evident tool provisioning
// manifest (trust release).
//
// Every external binary ANPU may execute is recorded as {tool, binary,
// install method + ref, resolved path, size, mtime, present}. Hashing the
// canonical manifest yields one short ID printed at scan start and by
// `anpu tools`, so a report reader can see exactly which tool set a scan
// ran with. File-content hashes are deliberately stat-only metadata
// (size+mtime, not full reads) so the scan-start line stays millisecond
// cheap; `tools install` prints a full sha256 once per install as the
// post-install verification.
package integrations

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ManifestEntry is one registry tool's provisioning record.
type ManifestEntry struct {
	// Tool is the canonical registry name.
	Tool string `json:"tool"`
	// Binary is the resolved executable name.
	Binary string `json:"binary"`
	// Method is the install method (go, pipx, apt, choco, docker, manual).
	Method string `json:"method"`
	// Ref is the install reference (module path, package, or image).
	Ref string `json:"ref"`
	// Path is the resolved binary path when installed.
	Path string `json:"path,omitempty"`
	// Size and ModTime identify the installed file (stat-only).
	Size    int64  `json:"size,omitempty"`
	ModTime string `json:"mtime,omitempty"`
	// Present reports whether the binary resolves right now.
	Present bool `json:"present"`
}

// manifestMethodRef renders the automated install method + ref for a
// recipe, or "manual" when only docs exist.
func manifestMethodRef(r Recipe) (method, ref string) {
	switch {
	case r.GoInstall != "":
		return "go", r.GoInstall
	case r.Pipx != "":
		return "pipx", r.Pipx
	case r.Apt != "":
		return "apt", r.Apt
	case r.Choco != "":
		return "choco", r.Choco
	case r.Docker != "":
		return "docker", r.Docker
	default:
		return "manual", r.Manual
	}
}

// Manifest records every registry tool. Pure except for PATH/existence
// stats (no subprocesses, no file-content reads).
func Manifest() []ManifestEntry {
	out := make([]ManifestEntry, 0, len(registryList))
	for _, r := range registryList {
		method, ref := manifestMethodRef(r)
		e := ManifestEntry{Tool: r.Name, Binary: r.Binary, Method: method, Ref: ref}
		if path, ok := LookupBinary(r.Binary); ok {
			e.Path = path
			e.Present = true
			if info, err := os.Stat(path); err == nil && !info.IsDir() { // #nosec G703 -- flagged path is the resolved vendor binary just located above.
				e.Size = info.Size()
				e.ModTime = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
			}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// ManifestHash returns the short tamper-evident ID of the manifest:
// sha256 over canonical tool|binary|method|ref|path|size|mtime|present
// lines, hex-encoded, first 12 characters.
func ManifestHash() string {
	var b strings.Builder
	for _, e := range Manifest() {
		fmt.Fprintf(&b, "%s|%s|%s|%s|%s|%d|%s|%v\n",
			e.Tool, e.Binary, e.Method, e.Ref, e.Path, e.Size, e.ModTime, e.Present)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return fmt.Sprintf("%x", sum)[:12]
}

// ManifestSummary renders the one-line scan-start/doctor record:
// "tools manifest <hash> (N/M present)".
func ManifestSummary() string {
	entries := Manifest()
	present := 0
	for _, e := range entries {
		if e.Present {
			present++
		}
	}
	return fmt.Sprintf("tools manifest %s (%d/%d present)", ManifestHash(), present, len(entries))
}

// VerifyBinary hashes an installed binary file (full sha256, once per
// install) for the post-install verification line.
func VerifyBinary(path string) (string, int64, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- flagged path is the resolved vendor binary just installed/verified.
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)[:12], int64(len(data)), nil
}
