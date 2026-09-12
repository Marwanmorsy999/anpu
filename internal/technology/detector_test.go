package technology

import (
	"strings"
	"testing"
)

// Bare-word body mentions (comparison/marketing copy) must not present as
// detected stack: low confidence + mention source flag.
func TestContentMentionSoftened(t *testing.T) {
	body := `<html><body><h1>Magento vs WooCommerce comparison</h1><p>We love WooCommerce and Magento.</p></body></html>`
	got := detectFromBody(body)
	seen := map[string]bool{}
	for _, tech := range got {
		if tech.Name != "WooCommerce" && tech.Name != "Magento" {
			continue
		}
		seen[tech.Name] = true
		if tech.Confidence > 0.5 {
			t.Fatalf("%s mention must be low confidence, got %v", tech.Name, tech.Confidence)
		}
		if !strings.Contains(tech.Evidence.Location, "mention") {
			t.Fatalf("%s must flag mention source, got %q", tech.Name, tech.Evidence.Location)
		}
		if !strings.Contains(tech.Evidence.Observed, "mentioned-in-content") {
			t.Fatalf("%s must say mentioned-in-content, got %q", tech.Name, tech.Evidence.Observed)
		}
	}
	if !seen["WooCommerce"] {
		t.Fatal("expected WooCommerce mention to be reported (softened, not dropped)")
	}
}

// Real asset signals keep normal confidence.
func TestAssetSignalKeepsConfidence(t *testing.T) {
	body := `<html><head><script src="/_next/static/chunks/app.js"></script></head></html>`
	for _, tech := range detectFromBody(body) {
		if tech.Name == "Next.js" && tech.Confidence < 0.5 {
			t.Fatalf("asset signal must keep confidence, got %v", tech.Confidence)
		}
	}
}
