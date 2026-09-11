package integrations

import "testing"

func TestRegistrableBase(t *testing.T) {
	cases := map[string]string{
		"www.example.com":     "example.com",
		"EXAMPLE.COM.":        "example.com",
		"localhost":           "localhost",
		"":                    "",
		"a.b.example.co.uk":   "example.co.uk",
		"example.co.uk":       "example.co.uk",
		"sub.example.com.au":  "example.com.au",
		"192.168.1.1":         "192.168.1.1",
		"deep.sub.example.io": "example.io",
	}
	for in, want := range cases {
		if got := registrableBase(in); got != want {
			t.Errorf("registrableBase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://example.com:8443/a?x=1#f": "example.com",
		"http://user:pass@example.com/x":   "example.com",
		"https://[::1]:8443/x":             "::1",
		"http://[2001:db8::1]/":            "2001:db8::1",
		"HTTPS://EXAMPLE.COM/Path":         "example.com",
		"notaurl":                          "",
		"":                                 "",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapSeverity(t *testing.T) {
	if mapSeverity("critical") != "critical" || mapSeverity("CRITICAL") != "critical" {
		t.Fatal("critical mapping must be case-insensitive")
	}
	if mapSeverity("high") != "high" || mapSeverity("medium") != "medium" || mapSeverity("low") != "low" {
		t.Fatal("basic mapping wrong")
	}
	if mapSeverity("something-new") != "info" {
		t.Fatalf("unknown must fall back to info, got %q", mapSeverity("something-new"))
	}
}

func TestFirstLinesAndTrimMiddle(t *testing.T) {
	got := firstLines([]byte("\nfoo\n\nbar\nbaz\nqux\n"), 2)
	if got != "foo | bar" {
		t.Fatalf("firstLines wrong: %q", got)
	}
	if trimMiddle("a  b   c", 100) != "a b c" {
		t.Fatalf("trimMiddle must collapse whitespace")
	}
	if trimMiddle("123456789", 5) != "12345..." {
		t.Fatalf("trimMiddle must truncate: %q", trimMiddle("123456789", 5))
	}
}
