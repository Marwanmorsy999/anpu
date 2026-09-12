package integrations

import (
	"strings"
	"testing"
)

func TestManifestCoversRegistry(t *testing.T) {
	entries := Manifest()
	if len(entries) != len(registryList) {
		t.Fatalf("manifest must cover %d recipes, got %d", len(registryList), len(entries))
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Tool == "" || e.Binary == "" || e.Method == "" {
			t.Fatalf("entry must name tool/binary/method: %+v", e)
		}
		if seen[e.Tool] {
			t.Fatalf("duplicate tool %q", e.Tool)
		}
		seen[e.Tool] = true
	}
}

func TestManifestHashStable(t *testing.T) {
	a, b := ManifestHash(), ManifestHash()
	if len(a) != 12 || a != b {
		t.Fatalf("hash must be a stable 12-hex ID, got %q vs %q", a, b)
	}
	if s := ManifestSummary(); !strings.Contains(s, a) || !strings.Contains(s, "present") {
		t.Fatalf("summary must carry hash + counts: %q", s)
	}
}

func TestManifestMethodRef(t *testing.T) {
	if m, _ := manifestMethodRef(Recipe{GoInstall: "example.com/x@latest"}); m != "go" {
		t.Fatalf("go recipe must report go, got %q", m)
	}
	if m, _ := manifestMethodRef(Recipe{Manual: "clone it"}); m != "manual" {
		t.Fatalf("manual recipe must report manual, got %q", m)
	}
}
