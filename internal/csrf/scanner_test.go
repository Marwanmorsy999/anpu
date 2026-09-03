package csrf

import (
	"testing"

	"github.com/anpu-project/anpu/pkg/models"
)

func TestIsMutationMethod(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{"POST", true},
		{"PUT", true},
		{"PATCH", true},
		{"DELETE", true},
		{"post", true}, // case-insensitive
		{"GET", false},
		{"HEAD", false},
		{"OPTIONS", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isMutationMethod(tc.method); got != tc.want {
			t.Errorf("isMutationMethod(%q) = %v, want %v", tc.method, got, tc.want)
		}
	}
}

func TestIsFormEndpoint(t *testing.T) {
	formPost := models.Endpoint{URL: "https://example.com/login", Method: "POST", Sources: []string{"html-form"}}
	formGet := models.Endpoint{URL: "https://example.com/search", Method: "GET", Sources: []string{"html-form"}}
	linkPost := models.Endpoint{URL: "https://example.com/api", Method: "POST", Sources: []string{"javascript"}}
	noMethod := models.Endpoint{URL: "https://example.com/page", Sources: []string{"html-link"}}

	if !isFormEndpoint(formPost) {
		t.Error("form POST should be a form endpoint")
	}
	if isFormEndpoint(formGet) {
		t.Error("form GET should not be a form endpoint")
	}
	if isFormEndpoint(linkPost) {
		t.Error("JS POST without html-form source should not be a form endpoint")
	}
	if isFormEndpoint(noMethod) {
		t.Error("no-method link should not be a form endpoint")
	}
}

func TestCSRFTokenPatternMatches(t *testing.T) {
	hits := []string{
		`<input type="hidden" name="_token" value="abc">`,
		`<input name="csrf_token" value="xyz">`,
		`<input name="authenticity_token" value="tok">`,
		`<input name="__RequestVerificationToken" value="tok">`,
		`<input name="_csrf" value="tok">`,
		`<input name="csrfmiddlewaretoken" value="tok">`,
		`<meta name="csrf-token" content="tok">`,
		`<meta name="x-csrf-token" content="tok">`,
		`<meta content="tok" name="X-XSRF-TOKEN">`,
	}
	for _, h := range hits {
		if !csrfTokenPattern.MatchString(h) {
			t.Errorf("pattern should match: %s", h)
		}
	}

	misses := []string{
		`<input type="text" name="username">`,
		`<form action="/submit" method="post">`,
		`<input name="email" value="">`,
	}
	for _, m := range misses {
		if csrfTokenPattern.MatchString(m) {
			t.Errorf("pattern should NOT match: %s", m)
		}
	}
}
