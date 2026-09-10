package deps

// Manifest harvesting (Master P2 + Wave 3 item 138): beyond JS asset
// filenames, dependency versions are harvested from package manifests
// discovered by the crawler (requirements.txt, package.json, pom.xml,
// go.mod, Cargo.lock, Gemfile.lock) and resolved to OSV ecosystems
// (PyPI, npm, Maven, Go, crates.io, RubyGems).
//
// Bounds: at most 3 manifest fetches per scan, only when the scanner was
// built with an HTTP client (NewWithClient). Failures are silent.

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
)

// maxManifestFetches bounds manifest HTTP fetches per scan.
const maxManifestFetches = 3

// manifestKind classifies a manifest URL by filename.
func manifestKind(rawURL string) string {
	lower := strings.ToLower(rawURL)
	// Strip query strings before matching the filename.
	if i := strings.Index(lower, "?"); i >= 0 {
		lower = lower[:i]
	}
	switch {
	case strings.HasSuffix(lower, "requirements.txt"):
		return "requirements"
	case strings.HasSuffix(lower, "package.json"):
		return "packagejson"
	case strings.HasSuffix(lower, "pom.xml"):
		return "pom"
	case strings.HasSuffix(lower, "go.mod"):
		return "gomod"
	case strings.HasSuffix(lower, "cargo.lock"):
		return "cargolock"
	case strings.HasSuffix(lower, "gemfile.lock"):
		return "gemfilelock"
	default:
		return ""
	}
}

// manifestDep is one name@version harvested from a manifest.
type manifestDep struct {
	name    string
	version string
}

// parseRequirementsTXT extracts `name==version` pins. Only exact pins are
// kept — range specifiers (>=, ~=) are imprecise for vulnerability matching.
func parseRequirementsTXT(data string) []manifestDep {
	var out []manifestDep
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments and environment markers.
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		// Strip extras: `name[extra]==1.0`.
		if i := strings.Index(name, "["); i >= 0 {
			name = name[:i]
		}
		if name == "" || version == "" {
			continue
		}
		out = append(out, manifestDep{name: name, version: version})
	}
	return out
}

// parsePackageJSON extracts dependencies + devDependencies versions,
// stripping npm range prefixes (^ ~ >= <= > < = and whitespace).
func parsePackageJSON(data string) []manifestDep {
	var doc struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		return nil
	}
	var out []manifestDep
	for _, m := range []map[string]string{doc.Dependencies, doc.DevDependencies} {
		for name, raw := range m {
			v := strings.TrimSpace(raw)
			v = strings.TrimLeft(v, "^~>=< =")
			// Take the leading dotted version before any range operator or ||.
			if i := strings.IndexAny(v, " |,"); i >= 0 {
				v = v[:i]
			}
			if name == "" || v == "" {
				continue
			}
			out = append(out, manifestDep{name: name, version: v})
		}
	}
	return out
}

// pomArtifactRe matches adjacent artifactId/version pairs (heuristic:
// covers dependency and parent blocks; good enough for version hints).
var pomArtifactRe = regexp.MustCompile(`(?s)<artifactId>\s*([^<>\s]+)\s*</artifactId>\s*<version>\s*([^<>\s]+)\s*</version>`)

// parsePomXML extracts (artifactId, version) pairs.
func parsePomXML(data string) []manifestDep {
	var out []manifestDep
	for _, m := range pomArtifactRe.FindAllStringSubmatch(data, -1) {
		if len(m) < 3 {
			continue
		}
		out = append(out, manifestDep{name: m[1], version: m[2]})
	}
	return out
}

// parseGoMod extracts module requirements (`path vX` lines), skipping
// directives (module/go/toolchain), replacements (=>), and retract blocks.
func parseGoMod(data string) []manifestDep {
	var out []manifestDep
	inBlock := false
	for _, line := range strings.Split(data, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.HasPrefix(trimmed, "require (") {
			inBlock = true
			continue
		}
		if inBlock && trimmed == ")" {
			inBlock = false
			continue
		}
		body := trimmed
		if strings.HasPrefix(body, "require ") && !inBlock {
			body = strings.TrimSpace(strings.TrimPrefix(body, "require "))
		} else if !inBlock {
			continue
		}
		if strings.Contains(body, "=>") {
			continue
		}
		fields := strings.Fields(body)
		if len(fields) < 2 {
			continue
		}
		out = append(out, manifestDep{name: fields[0], version: fields[1]})
	}
	return out
}

// cargoPkgRe matches `name = "x"` + `version = "y"` pairs inside
// Cargo.lock [[package]] blocks.
var cargoPkgRe = regexp.MustCompile(`(?m)^name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"`)

// parseCargoLock extracts (name, version) pairs from Cargo.lock.
func parseCargoLock(data string) []manifestDep {
	var out []manifestDep
	for _, m := range cargoPkgRe.FindAllStringSubmatch(data, -1) {
		if len(m) < 3 || m[1] == "" || m[2] == "" {
			continue
		}
		out = append(out, manifestDep{name: m[1], version: m[2]})
	}
	return out
}

// gemSpecRe matches indented `name (version)` lines in Gemfile.lock
// GEM specs (4-space indent distinguishes specs from sections).
var gemSpecRe = regexp.MustCompile(`(?m)^ {4}([A-Za-z0-9_\-]+) \(([0-9][^)]*)\)`)

// parseGemfileLock extracts (name, version) pairs from Gemfile.lock.
func parseGemfileLock(data string) []manifestDep {
	var out []manifestDep
	for _, m := range gemSpecRe.FindAllStringSubmatch(data, -1) {
		if len(m) < 3 || m[1] == "" || m[2] == "" {
			continue
		}
		out = append(out, manifestDep{name: m[1], version: strings.TrimSpace(m[2])})
	}
	return out
}

// fetchManifest fetches one manifest URL with a per-fetch timeout,
// capped by the client's own MaxBodyBytes bound.
func fetchManifest(ctx context.Context, client *anpuhttp.Client, rawURL string) (string, bool) {
	if client == nil {
		return "", false
	}
	fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := client.Get(fctx, rawURL)
	if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
		return "", false
	}
	return string(resp.Body), true
}

// harvestManifests fetches and parses up to maxManifestFetches manifests
// from the discovered endpoints. Returned deps are in endpoint order.
func harvestManifests(ctx context.Context, client *anpuhttp.Client, urls []string) []manifestDep {
	var out []manifestDep
	fetched := 0
	seenURL := map[string]bool{}
	for _, u := range urls {
		kind := manifestKind(u)
		if kind == "" || seenURL[u] {
			continue
		}
		if fetched >= maxManifestFetches {
			break
		}
		seenURL[u] = true
		body, ok := fetchManifest(ctx, client, u)
		fetched++
		if !ok {
			continue
		}
		var deps []manifestDep
		switch kind {
		case "requirements":
			deps = parseRequirementsTXT(body)
		case "packagejson":
			deps = parsePackageJSON(body)
		case "pom":
			deps = parsePomXML(body)
		case "gomod":
			deps = parseGoMod(body)
		case "cargolock":
			deps = parseCargoLock(body)
		case "gemfilelock":
			deps = parseGemfileLock(body)
		}
		out = append(out, deps...)
	}
	return out
}

// resolveManifestDep maps a harvested (name, version) to an OSV package
// across npm/PyPI/Maven/Go/crates.io/RubyGems. Go module paths resolve
// by full path first, then by basename (e.g. github.com/gin-gonic/gin
// → gin).
func resolveManifestDep(name, version string) (osvPackage, bool) {
	lib := canonical(name)
	if npm, ok := npmPackage(lib); ok {
		return osvPackage{display: lib, npm: npm, ecosystem: "npm", version: version}, true
	}
	if pypi, ok := pypiPackage(lib); ok {
		return osvPackage{display: lib, npm: pypi, ecosystem: "PyPI", version: version}, true
	}
	if maven, ok := mavenPackage(lib); ok {
		return osvPackage{display: lib, npm: maven, ecosystem: "Maven", version: version}, true
	}
	if goMod, ok := goPackage(lib); ok {
		return osvPackage{display: lib, npm: goMod, ecosystem: "Go", version: version}, true
	}
	if crate, ok := cratesPackage(lib); ok {
		return osvPackage{display: lib, npm: crate, ecosystem: "crates.io", version: version}, true
	}
	if gem, ok := rubygemsPackage(lib); ok {
		return osvPackage{display: lib, npm: gem, ecosystem: "RubyGems", version: version}, true
	}
	// Go basename fallback for full module paths.
	if i := strings.LastIndex(lib, "/"); i >= 0 {
		base := lib[i+1:]
		if goMod, ok := goPackage(base); ok {
			return osvPackage{display: base, npm: goMod, ecosystem: "Go", version: version}, true
		}
	}
	return osvPackage{}, false
}
