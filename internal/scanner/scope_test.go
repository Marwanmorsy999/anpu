package scanner

import (
	"net/url"
	"testing"
)

func scopeTarget(raw string) *ValidatedTarget {
	u, _ := url.Parse(raw)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	return &ValidatedTarget{Raw: raw, URL: u, Host: host}
}

func TestInScopeHost(t *testing.T) {
	sc := &ScanContext{Target: scopeTarget("https://vondera.app"), ScopeHosts: []string{"www.vondera.app"}}
	for _, h := range []string{"vondera.app", "Vondera.App", "www.vondera.app"} {
		if !sc.InScopeHost(h) {
			t.Fatalf("%q must be in scope", h)
		}
	}
	for _, h := range []string{"evil.com", "blog.vondera.app", ""} {
		if sc.InScopeHost(h) {
			t.Fatalf("%q must be out of scope", h)
		}
	}
	var nilSC *ScanContext
	if nilSC.InScopeHost("vondera.app") {
		t.Fatal("nil context must reject")
	}
}
