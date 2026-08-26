package integrations

import (
	"context"
	"testing"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

func TestZap_Name(t *testing.T) {
	if got := NewZapScanner().Name(); got != "zap" {
		t.Fatalf("got %q", got)
	}
}

func TestZap_AlwaysUnavailable(t *testing.T) {
	if NewZapScanner().Available(context.Background()) {
		t.Fatal("expected ZAP to be unavailable in MVP")
	}
}

func TestZap_Run_ReturnsWarningNotError(t *testing.T) {
	vt, err := scanner.ValidateTarget("http://127.0.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewZapScanner().Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("expected one warning, got %v", res.Warnings)
	}
}
