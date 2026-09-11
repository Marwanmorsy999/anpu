package integrations

import (
	"net/url"
	"testing"

	"github.com/anpu-project/anpu/internal/scanner"
)

func testScanContext() *scanner.ScanContext {
	u, _ := url.Parse("https://example.com")
	return &scanner.ScanContext{Target: &scanner.ValidatedTarget{Raw: "https://example.com", URL: u, Host: "example.com"}}
}

func TestParseFuzzerStatuses(t *testing.T) {
	spec := &ToolSpec{Name: "ffuf", Binary: "ffuf"}
	out := []byte("admin\t[Status: 200, Size: 123]\nlogin\t[Status: 403, Size: 45]\nmissing\t[Status: 404, Size: 9]\n")
	fs, _ := parseFuzzer(spec, testScanContext(), out, "ffuf -u https://example.com/FUZZ")
	if len(fs) != 2 {
		t.Fatalf("404 must be skipped, got %d findings", len(fs))
	}
	if string(fs[0].Severity) != "info" || string(fs[1].Severity) != "low" {
		t.Fatalf("200->info, 401/403->low; got %s, %s", fs[0].Severity, fs[1].Severity)
	}
}

func TestParseFuzzerGobusterShape(t *testing.T) {
	spec := &ToolSpec{Name: "gobuster", Binary: "gobuster"}
	out := []byte("/backup (Status: 200)\n")
	fs, _ := parseFuzzer(spec, testScanContext(), out, "repro")
	if len(fs) != 1 {
		t.Fatalf("gobuster line must parse, got %d", len(fs))
	}
}

func TestParseNiktoKeywords(t *testing.T) {
	spec := &ToolSpec{Name: "nikto", Binary: "nikto"}
	out := []byte("+ Server: nginx/1.24\n+ OSVDB-1234: vulnerable script found\n- not a finding\n")
	fs, _ := parseNikto(spec, testScanContext(), out, "repro")
	if len(fs) != 2 {
		t.Fatalf("only '+ ' lines parse, got %d", len(fs))
	}
	if string(fs[0].Severity) != "info" || string(fs[1].Severity) != "low" {
		t.Fatalf("keyword line must be low, got %s / %s", fs[0].Severity, fs[1].Severity)
	}
}

func TestParsePortsShapes(t *testing.T) {
	spec := &ToolSpec{Name: "nmap", Binary: "nmap"}
	nmap := []byte("Host: 93.184.216.34 ()\tPorts: 80/open/tcp//http///, 443/closed/tcp//https///\n")
	fs, _ := parsePorts(spec, testScanContext(), nmap, "repro")
	if len(fs) != 1 {
		t.Fatalf("only open ports, got %d: %+v", len(fs), fs)
	}
	masscan := []byte("open tcp 80 93.184.216.34 12345\n")
	fs, _ = parsePorts(spec, testScanContext(), masscan, "repro")
	if len(fs) != 1 {
		t.Fatalf("masscan shape must parse, got %d", len(fs))
	}
}
