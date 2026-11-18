package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Marwanmorsy999/anpu/pkg/version"
	"github.com/spf13/cobra"
)

var updateCheck bool

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update ANPU to the latest release",
		Long: `Check the latest ANPU release on GitHub, download the matching
asset for this OS/architecture, verify its SHA-256 checksum (and the
cosign signature when cosign is installed), and replace the running
binary atomically. Network access is limited to github.com.

Use --check to only report whether an update is available.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(cmd)
		},
	}
	cmd.Flags().BoolVar(&updateCheck, "check", false, "only check for an update; do not download or replace")
	return cmd
}

func runUpdate(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(out, format, a...) }

	latest, err := resolveLatestTag()
	if err != nil {
		return fmt.Errorf("resolving latest release: %w", err)
	}
	// Defense in depth: resolveLatestTag already validates, but every
	// consumer of the tag (asset name, download URL) re-checks so a
	// future refactor cannot reintroduce an unvalidated tag flow.
	if err := validReleaseTag(latest); err != nil {
		return fmt.Errorf("refusing hostile release tag: %w", err)
	}
	p("current version: %s\n", version.Version)
	p("latest version:  %s\n", latest)

	if strings.TrimPrefix(latest, "v") == version.Version {
		p("already up to date\n")
		return nil
	}
	if updateCheck {
		p("update available\n")
		return nil
	}

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	if goos == "windows" {
		goos = "windows"
	}
	asset := fmt.Sprintf("anpu_%s_%s_%s", strings.TrimPrefix(latest, "v"), goos, goarch)
	if goos == "windows" {
		asset += ".zip"
	} else {
		asset += ".tar.gz"
	}

	base := "https://github.com/Marwanmorsy999/anpu/releases/download/" + latest
	tmpDir, err := os.MkdirTemp("", "anpu-update-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	p("downloading %s...\n", asset)
	archivePath := filepath.Join(tmpDir, asset)
	if err := downloadFile(base+"/"+asset, archivePath); err != nil {
		return err
	}
	checksumsPath := filepath.Join(tmpDir, "checksums.txt")
	if err := downloadFile(base+"/checksums.txt", checksumsPath); err != nil {
		return err
	}

	// verify checksum
	line := findChecksumLine(checksumsPath, asset)
	if line == "" {
		return fmt.Errorf("checksum entry for %s not found", asset)
	}
	want := strings.Fields(line)[0]
	got, err := sha256File(archivePath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(want, got) {
		return fmt.Errorf("checksum mismatch (want %s, got %s)", want, got)
	}
	p("checksum verified\n")

	// cosign (optional)
	if cosignPath, err := exec.LookPath("cosign"); err == nil {
		sigPath := filepath.Join(tmpDir, "checksums.txt.sigstore.json")
		if err := downloadFile(base+"/checksums.txt.sigstore.json", sigPath); err == nil {
			cmd := exec.Command(cosignPath, "verify-blob", "--bundle", sigPath, // #nosec G204
				"--certificate-identity-regexp", "^https://github.com/Marwanmorsy999/anpu/\\.github/workflows/release\\.yml@refs/tags/.*$",
				"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
				checksumsPath)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("cosign verification failed: %v\n%s", err, string(out))
			}
			p("cosign signature verified\n")
		}
	} else {
		p("cosign not found, skipping signature verification\n")
	}

	// extract binary
	binaryPath := filepath.Join(tmpDir, "anpu")
	if goos == "windows" {
		binaryPath += ".exe"
	}
	if goos == "windows" {
		// zip
		if err := unzipFirst(archivePath, tmpDir, "anpu.exe"); err != nil {
			return err
		}
	} else {
		// tar.gz
		if err := extractTarGz(archivePath, tmpDir); err != nil {
			return err
		}
	}
	if _, err := os.Stat(binaryPath); err != nil { // #nosec G304
		return fmt.Errorf("archive did not contain anpu binary")
	}

	// replace atomically
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	newPath := exe + ".new"
	if err := copyFile(binaryPath, newPath); err != nil {
		return err
	}
	if err := os.Chmod(newPath, 0o755); err != nil { // #nosec G302
		return err
	}

	if runtime.GOOS == "windows" {
		oldPath := exe + ".old"
		_ = os.Remove(oldPath)
		if err := os.Rename(exe, oldPath); err != nil {
			return err
		}
		if err := os.Rename(newPath, exe); err != nil {
			_ = os.Rename(oldPath, exe)
			return err
		}
		_ = os.Remove(oldPath)
	} else {
		if err := os.Rename(newPath, exe); err != nil {
			return err
		}
	}

	p("updated to %s\n", latest)
	// final version check
	cmd2 := exec.Command(exe, "version") // #nosec G204
	if out, err := cmd2.CombinedOutput(); err == nil {
		p("%s", string(out))
	}
	return nil
}

func resolveLatestTag() (string, error) {
	return resolveLatestTagFrom("https://github.com/Marwanmorsy999/anpu/releases/latest")
}

// resolveLatestTagFrom resolves the latest release tag by following the
// /releases/latest redirect once and parsing the tag from the Location
// header. The tag is untrusted input — it comes from whatever answered
// the redirect — so it must pass validReleaseTag before any use (asset
// name, download URL, extracted archive path).
func resolveLatestTagFrom(latestURL string) (string, error) {
	req, err := http.NewRequest("GET", latestURL, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("no redirect location")
	}
	parts := strings.Split(strings.TrimRight(loc, "/"), "/")
	tag := parts[len(parts)-1]
	if err := validReleaseTag(tag); err != nil {
		return "", fmt.Errorf("hostile release tag in %q: %w", loc, err)
	}
	return tag, nil
}

// validReleaseTag rejects anything outside a strict release-tag charset.
// The tag flows into the download asset name and URL, and previously into
// a fmt.Sprintf-built PowerShell command, so a single quote, newline, or
// shell metacharacter in a hostile redirect (DNS hijack, compromised
// mirror, malicious proxy) must be refused before it can influence any
// string that ends up in a command or URL. Allowed: v-prefixed semver-ish
// tags such as v0.5.7, v1.2.3-rc.1, v2.0.0+build.5.
func validReleaseTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("empty tag")
	}
	if len(tag) > 64 {
		return fmt.Errorf("tag too long (%d bytes)", len(tag))
	}
	if !strings.HasPrefix(tag, "v") {
		return fmt.Errorf("tag must start with 'v'")
	}
	if strings.Contains(tag, "..") {
		return fmt.Errorf("tag must not contain '..'")
	}
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == '+':
		default:
			return fmt.Errorf("illegal character %q in tag", r)
		}
	}
	// Must contain at least one digit after the v prefix so words like
	// "vanilla" cannot pose as versions.
	for _, r := range tag[1:] {
		if r >= '0' && r <= '9' {
			return nil
		}
	}
	return fmt.Errorf("tag carries no version digits")
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url) // #nosec G107
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	f, err := os.Create(dest) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, resp.Body)
	return err
}

func findChecksumLine(path, name string) string {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == name {
			return line
		}
	}
	return ""
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst) // #nosec G304
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	_, err = io.Copy(out, in)
	return err
}

func extractTarGz(archive, dest string) error {
	// use tar via os/exec to avoid adding deps
	cmd := exec.Command("tar", "-xzf", archive, "-C", dest) // #nosec G204
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tar extract failed: %v\n%s", err, string(out))
	}
	return nil
}

// unzipFirst extracts a release zip IN-PROCESS with archive/zip.
//
// The previous implementation shelled out to PowerShell with a
// fmt.Sprintf-built command:
//
//	powershell -Command "Expand-Archive -Path '<archive>' -DestinationPath '<dest>' -Force"
//
// A hostile release tag (see validReleaseTag) could carry a single quote
// and break out of the quoting to run arbitrary PowerShell — command
// injection from a redirect the operator does not control. In-process
// extraction removes the interpreter entirely: no quoting, no shell, no
// injection surface. Path traversal entries (Zip-Slip, e.g. "../evil.exe")
// are refused instead of written outside dest.
func unzipFirst(archive, dest, name string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer func() { _ = r.Close() }()

	destClean := filepath.Clean(dest) + string(os.PathSeparator)
	extracted := 0
	for _, f := range r.File {
		// Zip-Slip guard: the resolved target must stay inside dest.
		target := filepath.Join(dest, f.Name) // #nosec G305 -- target is validated against destClean on the following line
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), destClean) {
			return fmt.Errorf("zip entry %q escapes destination — refusing", f.Name)
		}
		if err := extractZipEntry(f, target); err != nil {
			return err
		}
		extracted++
	}
	if extracted == 0 {
		return fmt.Errorf("release zip is empty")
	}
	return nil
}

// extractZipEntry streams one zip entry to target with mode 0755,
// refusing symlinks and hardlinks (a release archive never contains
// them; following one would write outside dest).
func extractZipEntry(f *zip.File, target string) error {
	switch f.Mode() & os.ModeType {
	case os.ModeSymlink, os.ModeNamedPipe, os.ModeDevice:
		return fmt.Errorf("zip entry %q is a symlink/device — refusing", f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open entry %q: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil { // #nosec G301 -- update staging dir, not a secret
		return fmt.Errorf("create dir for %q: %w", f.Name, err)
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode().Perm()) // #nosec G304 -- target is dest-joined and Zip-Slip checked in unzipFirst
	if err != nil {
		return fmt.Errorf("create %q: %w", target, err)
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, rc); err != nil { // #nosec G110 -- release zip comes from the checksum-verified GitHub download (sha256 checked before extraction)
		return fmt.Errorf("write %q: %w", target, err)
	}
	return nil
}
