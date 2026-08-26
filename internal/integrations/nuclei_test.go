package integrations

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
)

func init() { scanner.AllowLocalNetwork = true }

func TestNuclei_Name(t *testing.T) {
	if got := NewNucleiScanner().Name(); got != "nuclei" { t.Fatalf("got %q", got) }
}

func TestNuclei_AvailableFalse_WhenBinaryMissing(t *testing.T) {
	n := &NucleiScanner{BinaryPath: filepath.Join(t.TempDir(), "missing-nuclei")}
	if n.Available(context.Background()) { t.Fatal("expected unavailable") }
}

func TestNuclei_Run_NotInstalled_ReturnsWarning(t *testing.T) {
	n := &NucleiScanner{BinaryPath: filepath.Join(t.TempDir(), "missing-nuclei"), Timeout: 5 * time.Second}
	vt, err := scanner.ValidateTarget("http://127.0.0.1/")
	if err != nil { t.Fatal(err) }
	res, err := n.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil { t.Fatal(err) }
	if len(res.Warnings) == 0 || len(res.Findings) != 0 { t.Fatalf("expected warning/no findings, got warnings=%v findings=%v", res.Warnings, res.Findings) }
}

func fakeNucleiScript(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" { t.Skip("POSIX fake nuclei script is not portable to Windows") }
	path := filepath.Join(t.TempDir(), "nuclei")
	script := `#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "-version" ]; then
    echo "fake-nuclei 0.0.0"
    exit 0
  fi
done
echo '{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"medium","description":"An admin panel is exposed.","classification":{"cwe-id":["CWE-200"]}},"matched-at":"http://127.0.0.1/admin","matcher-name":"panel-detect","type":"http","host":"127.0.0.1"}'
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { t.Fatal(err) }
	return path
}

func TestNuclei_Run_ParsesFindings(t *testing.T) {
	n := &NucleiScanner{BinaryPath: fakeNucleiScript(t), Timeout: 10 * time.Second}
	vt, err := scanner.ValidateTarget("http://127.0.0.1/")
	if err != nil { t.Fatal(err) }
	res, err := n.Run(context.Background(), &scanner.ScanContext{Target: vt, Config: models.ScanConfig{Profile: models.ProfileSafe}})
	if err != nil { t.Fatal(err) }
	if len(res.Findings) != 1 { t.Fatalf("expected one finding, got %+v", res.Findings) }
	f := res.Findings[0]
	if f.ID != "nuclei-exposed-panel" || f.Severity != models.SeverityMedium || f.CWE != "CWE-200" || f.Source != models.SourceNuclei {
		t.Fatalf("unexpected normalized finding: %+v", f)
	}
}

func TestNucleiTemplateTagsForProfile(t *testing.T) {
	cases := []struct{ profile models.Profile; want string }{
		{models.ProfileSafe, "info,low,medium"},
		{models.ProfileStandard, "info,low,medium,high"},
		{models.ProfileDeep, "info,low,medium,high,critical"},
	}
	for _, tc := range cases {
		if got := strings.Join(nucleiTemplateTagsForProfile(tc.profile), " "); !strings.Contains(got, tc.want) { t.Errorf("profile %s: got %q", tc.profile, got) }
	}
}

func TestConvertNucleiFinding_InvalidSeverityDefaultsToInfo(t *testing.T) {
	nl := nucleiJSONLine{TemplateID: "weird-template"}
	nl.Info.Severity = "not-a-real-severity"
	if got := convertNucleiFinding(nl, "http://example.com").Severity; got != models.SeverityInfo { t.Fatalf("got %s", got) }
}
