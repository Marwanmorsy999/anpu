package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestLoad_MissingFileReturnsEmptyConfig(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if f.Target.URL != "" {
		t.Error("expected empty config for missing file")
	}
}

func TestLoad_ParsesYAML(t *testing.T) {
	content := `
target:
  url: https://example.com

scan:
  profile: standard

modules:
  recon: true
  nuclei: false
  zap: false

report:
  html: true
  json: true
  sarif: false
`
	path := filepath.Join(t.TempDir(), "anpu.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Target.URL != "https://example.com" {
		t.Errorf("expected target.url to be parsed, got %q", f.Target.URL)
	}
	if f.Scan.Profile != "standard" {
		t.Errorf("expected scan.profile=standard, got %q", f.Scan.Profile)
	}
	if f.Modules.Nuclei == nil || *f.Modules.Nuclei != false {
		t.Error("expected modules.nuclei=false to be parsed as explicit false")
	}
	if f.Modules.Recon == nil || *f.Modules.Recon != true {
		t.Error("expected modules.recon=true to be parsed as explicit true")
	}
}

func TestResolveModules_CLIFlagsOverrideConfig(t *testing.T) {
	trueVal := true
	f := &File{Modules: ModulesFileConfig{Nuclei: &trueVal}}

	mc := ResolveModules(models.ProfileStandard, f, true /* --no-nuclei */, false, false, false)
	if mc.Nuclei {
		t.Error("expected --no-nuclei CLI flag to override modules.nuclei=true from config")
	}
}

func TestResolveModules_ProfileDefaultsApplyWithoutConfig(t *testing.T) {
	mc := ResolveModules(models.ProfileSafe, &File{}, false, false, false, false)
	if mc.Nuclei {
		t.Error("expected nuclei to default to disabled under the safe profile")
	}
	if !mc.Headers {
		t.Error("expected headers analysis to default to enabled")
	}
}
