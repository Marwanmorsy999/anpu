package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/plugins"
)

func TestPluginExampleRegistered(t *testing.T) {
	p, ok := plugins.Lookup("example-generator-meta")
	if !ok {
		t.Fatal("example plugin must be registered in the CLI binary")
	}
	if p.Description() == "" {
		t.Fatal("example plugin needs a description")
	}
	if len(plugins.List()) == 0 {
		t.Fatal("plugin list must not be empty")
	}
}

func runPluginCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newPluginCmd()
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestPluginInitScaffolds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "myplug")
	if err := runPluginCmd(t, "init", "--dir", dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"mycheck.yaml", "mycheck.go"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("init must write %s: %v", f, err)
		}
	}
	// The scaffolded YAML must load: init output is valid plugin input.
	checks, err := plugins.LoadChecks(filepath.Join(dir, "mycheck.yaml"))
	if err != nil || len(checks) != 1 {
		t.Fatalf("scaffolded YAML must load: %v %+v", checks, err)
	}
}

func TestPluginRunFlagValidation(t *testing.T) {
	// No network is touched: all three fail on flag validation first.
	if err := runPluginCmd(t, "run", "https://example.com"); err == nil ||
		!strings.Contains(err.Error(), "--plugin") {
		t.Fatalf("missing source must error, got %v", err)
	}
	if err := runPluginCmd(t, "run", "--plugin", "a.yaml", "--name", "b", "https://example.com"); err == nil {
		t.Fatal("both sources must error")
	}
	if err := runPluginCmd(t, "run", "--name", "example-generator-meta", "--format", "yaml", "https://example.com"); err == nil {
		t.Fatal("bad format must error")
	}
	if err := runPluginCmd(t, "run", "--name", "no-such-plugin", "https://example.com"); err == nil {
		t.Fatal("unknown plugin must error")
	}
}

func TestPluginCmdRegistered(t *testing.T) {
	root := newRootCmd()
	for _, c := range root.Commands() {
		if c.Name() == "plugin" {
			if c.GroupID != "setup" {
				t.Fatalf("plugin must be in setup group, got %q", c.GroupID)
			}
			return
		}
	}
	t.Fatal("plugin command not registered")
}
