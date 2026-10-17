package main

import (
	"testing"

	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// TestProfileDefaultsAndGuards pins safety-critical profile defaults:
// ultra is never the default, ZAP (an active DAST scanner) is enabled only
// on ultra, and the local-network guard is off by default.
func TestProfileDefaultsAndGuards(t *testing.T) {
	if models.DefaultModuleConfig(models.ProfileSafe).ZAP {
		t.Fatal("safe profile must not enable ZAP")
	}
	if models.DefaultModuleConfig(models.ProfileAdvanced).ZAP {
		t.Fatal("advanced profile must not enable ZAP")
	}
	if !models.DefaultModuleConfig(models.ProfileUltra).ZAP {
		t.Fatal("ultra profile must enable ZAP")
	}
	if scanner.AllowLocalNetwork {
		t.Fatal("local-network guard must be off by default")
	}
}

// TestScanDefaultProfileIsSafe ensures the --profile flag defaults to safe,
// never ultra, so an active scan is never the default behavior.
func TestScanDefaultProfileIsSafe(t *testing.T) {
	cmd := newScanCmd()
	f := cmd.Flags().Lookup("profile")
	if f == nil {
		t.Fatal("scan command has no --profile flag")
	}
	if f.DefValue != "safe" {
		t.Fatalf("--profile default must be safe, got %q", f.DefValue)
	}
}
