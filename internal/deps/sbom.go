package deps

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// sbom.go — CycloneDX 1.4 software-bill-of-materials emit for the
// resolved package inventory (Phase B). Best-effort file write into the
// report output dir; failures warn, never fail the stage.

// cyclonedxComponent is one library entry.
type cyclonedxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

// cyclonedxBOM is the minimal CycloneDX 1.4 document ANPU emits.
type cyclonedxBOM struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Timestamp string `json:"timestamp"`
		Tools     []struct {
			Vendor string `json:"vendor"`
			Name   string `json:"name"`
		} `json:"tools"`
	} `json:"metadata"`
	Components []cyclonedxComponent `json:"components"`
}

// purlFor builds a best-effort package URL for an OSV package.
// Unknown ecosystems degrade to pkg:generic.
func purlFor(p osvPackage) string {
	name := strings.TrimSpace(p.npm)
	if name == "" {
		name = strings.TrimSpace(p.display)
	}
	ver := ""
	if strings.TrimSpace(p.version) != "" {
		ver = "@" + strings.TrimSpace(p.version)
	}
	switch p.ecosystem {
	case "npm":
		return "pkg:npm/" + name + ver
	case "PyPI":
		return "pkg:pypi/" + name + ver
	case "Maven":
		// group:artifact → pkg:maven/group/artifact@version.
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 {
			return "pkg:maven/" + parts[0] + "/" + parts[1] + ver
		}
		return "pkg:maven/" + name + ver
	case "Go":
		return "pkg:golang/" + strings.ToLower(name) + ver
	case "crates.io":
		return "pkg:cargo/" + name + ver
	case "RubyGems":
		return "pkg:gem/" + name + ver
	default:
		return "pkg:generic/" + name + ver
	}
}

// slugHost reduces a target to a filename-safe host token.
func slugHost(rawURL string) string {
	lower := strings.ToLower(strings.TrimSpace(rawURL))
	lower = strings.TrimPrefix(strings.TrimPrefix(lower, "https://"), "http://")
	if i := strings.IndexAny(lower, "/?#"); i >= 0 {
		lower = lower[:i]
	}
	var b strings.Builder
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}

// writeSBOM serializes pkgs as CycloneDX 1.4 into outputDir and returns
// the written path. Callers treat errors as warnings, never failures.
func writeSBOM(outputDir, target string, pkgs []osvPackage) (string, error) {
	seen := map[string]bool{}
	bom := cyclonedxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
	}
	bom.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	bom.Metadata.Tools = []struct {
		Vendor string `json:"vendor"`
		Name   string `json:"name"`
	}{{Vendor: "anpu-project", Name: "anpu-deps"}}
	for _, p := range pkgs {
		name := strings.TrimSpace(p.npm)
		if name == "" {
			name = strings.TrimSpace(p.display)
		}
		if name == "" || seen[name+"@"+p.version] {
			continue
		}
		seen[name+"@"+p.version] = true
		bom.Components = append(bom.Components, cyclonedxComponent{
			Type: "library", Name: name, Version: strings.TrimSpace(p.version), PURL: purlFor(p),
		})
	}
	if len(bom.Components) == 0 {
		return "", fmt.Errorf("no resolved components")
	}
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(outputDir, fmt.Sprintf("sbom-%s-%s.cyclonedx.json",
		slugHost(target), time.Now().Format("2006-01-02-150405")))
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
