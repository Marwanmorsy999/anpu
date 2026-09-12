package adaptive

import (
	"strings"
	"testing"

	"github.com/Marwanmorsy999/anpu/pkg/models"
)

func eps(urls ...string) []models.Endpoint {
	var out []models.Endpoint
	for _, u := range urls {
		out = append(out, models.Endpoint{URL: u, Category: models.EndpointPage})
	}
	return out
}

func TestStaticMarketingClassified(t *testing.T) {
	class, reason := SurfaceClass(
		eps("https://example.com/", "https://example.com/about"),
		[]models.Technology{{Name: "Gatsby", Category: "framework", Confidence: 0.9}},
		false,
	)
	if class != ClassStaticMarketing {
		t.Fatalf("SSG without API/auth/forms/params must be static-marketing, got %q", class)
	}
	if !strings.Contains(reason, "static-marketing") {
		t.Fatalf("reason must say why: %q", reason)
	}
}

func TestAppTriggers(t *testing.T) {
	ssg := []models.Technology{{Name: "Hugo", Category: "framework", Confidence: 0.9}}
	cases := []struct {
		name      string
		endpoints []models.Endpoint
		authed    bool
	}{
		{"api", []models.Endpoint{{URL: "https://example.com/api", Category: models.EndpointAPI}}, false},
		{"auth", []models.Endpoint{{URL: "https://example.com/login", Category: models.EndpointAuth}}, false},
		{"params", eps("https://example.com/?q=1"), false},
		{"authed", eps("https://example.com/"), true},
		{"no-ssg", eps("https://example.com/"), false},
	}
	for _, c := range cases {
		techs := ssg
		if c.name == "no-ssg" {
			techs = nil
		}
		if class, _ := SurfaceClass(c.endpoints, techs, c.authed); class != ClassApp {
			t.Fatalf("%s must stay app, got %q", c.name, class)
		}
	}
	forms := []models.Endpoint{{URL: "https://example.com/", Category: models.EndpointPage, Method: "POST"}}
	if class, _ := SurfaceClass(forms, ssg, false); class != ClassApp {
		t.Fatalf("forms must stay app, got %q", class)
	}
}

func TestFailOpenOnEmptyDiscovery(t *testing.T) {
	if class, _ := SurfaceClass(nil, nil, false); class != ClassApp {
		t.Fatalf("empty discovery must fail open to app, got %q", class)
	}
}

func TestSkipRuleSet(t *testing.T) {
	for _, id := range []string{"sqli-error-based", "sqli-boolean-differential", "ssti-math-probe", "path-traversal", "cmd-injection-indicator"} {
		if !StaticMarketingSkipRules[id] {
			t.Fatalf("rule %q must be skipped on static-marketing", id)
		}
	}
	if StaticMarketingSkipRules["xss-reflected"] {
		t.Fatal("XSS must keep running on static-marketing")
	}
}
