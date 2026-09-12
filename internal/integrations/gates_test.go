package integrations

import (
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// Phase 4: new gates must skip loudly with reasons and fail open on
// empty intel (unknown stack/endpoints still run the tool).
func gateCtx() *scanner.ScanContext {
	return &scanner.ScanContext{Target: &scanner.ValidatedTarget{Raw: "https://example.com", Host: "example.com"}}
}

func endpointsOf(urls ...string) []models.Endpoint {
	var out []models.Endpoint
	for _, u := range urls {
		out = append(out, models.Endpoint{URL: u})
	}
	return out
}

func technologiesOf(names ...string) []models.Technology {
	var out []models.Technology
	for _, n := range names {
		out = append(out, models.Technology{Name: n})
	}
	return out
}

func TestGateReasons(t *testing.T) {
	kiterunner, ok := SpecByName("kiterunner")
	if !ok {
		t.Fatal("kiterunner spec missing")
	}
	// Empty intel fails open.
	if r := gateReason(kiterunner, gateCtx()); r != "" {
		t.Fatalf("empty intel must fail open, got %q", r)
	}
	// Non-API surface skips kiterunner.
	boring := gateCtx()
	boring.Endpoints = endpointsOf("https://example.com/about", "https://example.com/contact")
	if r := gateReason(kiterunner, boring); !strings.Contains(r, "API") {
		t.Fatalf("non-API surface must skip kiterunner, got %q", r)
	}
	// API endpoint runs it.
	api := gateCtx()
	api.Endpoints = endpointsOf("https://example.com/api/v1/users")
	if r := gateReason(kiterunner, api); r != "" {
		t.Fatalf("API surface must run kiterunner, got %q", r)
	}
	// API tech signal runs it too.
	apitech := gateCtx()
	apitech.Endpoints = endpointsOf("https://example.com/about")
	apitech.Technologies = technologiesOf("Django REST framework")
	if r := gateReason(kiterunner, apitech); r != "" {
		t.Fatalf("API stack must run kiterunner, got %q", r)
	}
	// Rich endpoint yield skips archive tools.
	rich := gateCtx()
	for i := 0; i < 45; i++ {
		rich.Endpoints = append(rich.Endpoints, models.Endpoint{URL: "https://example.com/page" + string(rune('a'+i%26)) + string(rune('0'+i/26))})
	}
	gau, _ := SpecByName("gau")
	if r := gateReason(gau, rich); !strings.Contains(r, "rich native endpoint") {
		t.Fatalf("rich yield must skip gau, got %q", r)
	}
	wayback, _ := SpecByName("waybackurls")
	if r := gateReason(wayback, rich); r == "" {
		t.Fatal("rich yield must skip waybackurls")
	}
	// ...but not the fuzzer whose wordlist adds depth.
	ffuf, _ := SpecByName("ffuf")
	if r := gateReason(ffuf, rich); r != "" {
		t.Fatalf("fuzzers must not yield-gate, got %q", r)
	}
	// Rich subdomain yield skips slow brute-forcers (amass + family).
	full := gateCtx()
	for i := 0; i < 12; i++ {
		full.Subdomains = append(full.Subdomains, "host"+string(rune('a'+i))+".example.com")
	}
	for _, name := range []string{"amass", "shuffledns", "puredns"} {
		s, _ := SpecByName(name)
		if r := gateReason(s, full); !strings.Contains(r, "subdomain yield") {
			t.Fatalf("%s must yield-gate, got %q", name, r)
		}
	}
	// CMS stack gate still works.
	wpscan, _ := SpecByName("wpscan")
	wp := gateCtx()
	wp.Technologies = technologiesOf("nginx server")
	if r := gateReason(wpscan, wp); !strings.Contains(r, "wordpress") {
		t.Fatalf("non-WP stack must skip wpscan, got %q", r)
	}
	// Nil context fails open.
	if r := gateReason(kiterunner, nil); r != "" {
		t.Fatalf("nil context must fail open, got %q", r)
	}
}
