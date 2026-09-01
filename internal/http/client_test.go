package http

import (
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestClient_RejectsDirectPrivateIP(t *testing.T) {
	c := NewClient()
	_, err := c.Get(context.Background(), "http://127.0.0.1:1/")
	if err == nil {
		t.Fatal("expected direct private IP to be rejected")
	}
}

func TestClient_RejectsLocalhostRedirect(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Location", "http://localhost:1/")
		w.WriteHeader(stdhttp.StatusFound)
	}))
	defer server.Close()

	c := NewClient()
	_, err := c.Get(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected redirect to localhost to be rejected")
	}
}

func TestClient_RejectsHostnameResolvingToPrivateAddressAtDial(t *testing.T) {
	c := NewClient()
	c.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("unused resolver dial")
		},
	}

	// A literal private address exercises the same safe-dial path without
	// depending on the machine's DNS configuration.
	_, err := c.safeDialContext(context.Background(), "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected safeDialContext to reject a loopback address")
	}
}

func TestClient_RejectsHostnameRedirectResolvingToPrivateAddress(t *testing.T) {
	c := NewClient()
	c.resolver = fakeResolver{ips: []net.IP{net.ParseIP("10.0.0.5")}}

	req := &stdhttp.Request{URL: mustParseURL(t, "http://internal.test:8080/")}
	if err := c.guardRedirectTarget(req); err == nil {
		t.Fatal("expected redirect to hostname resolving to a private address to be rejected")
	}
}

func TestClient_DialRechecksDNSAfterEarlierPublicValidation(t *testing.T) {
	c := NewClient()
	c.resolver = &sequenceResolver{results: [][]net.IP{
		{net.ParseIP("8.8.8.8")},
		{net.ParseIP("127.0.0.1")},
	}}

	req := &stdhttp.Request{URL: mustParseURL(t, "http://rebind.test:80/")}
	if err := c.guardRedirectTarget(req); err != nil {
		t.Fatalf("expected initial public DNS result to pass early redirect validation: %v", err)
	}
	_, err := c.safeDialContext(context.Background(), "tcp", "rebind.test:80")
	if err == nil {
		t.Fatal("expected safeDialContext to reject the rebinding to loopback")
	}
}

type fakeResolver struct {
	ips []net.IP
}

func (r fakeResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return r.ips, nil
}

type sequenceResolver struct {
	results [][]net.IP
	calls   int
}

func (r *sequenceResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	result := r.results[r.calls]
	r.calls++
	return result, nil
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse test URL: %v", err)
	}
	return u
}

func TestClient_LocalNetworkOverrideAllowsFixture(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusNoContent)
	}))
	defer server.Close()

	c := NewClientWithLocalNetworkAllowed(true)
	resp, err := c.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("expected local fixture to be reachable with explicit override: %v", err)
	}
	if resp.StatusCode != stdhttp.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}

func TestCheckIPNotPrivate_RejectsSpecialRanges(t *testing.T) {
	cases := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"169.254.169.254",
		"100.64.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"198.51.100.1",
		"203.0.113.1",
		"224.0.0.1",
	}
	for _, raw := range cases {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("failed to parse test IP %s", raw)
		}
		if err := checkIPNotPrivate(ip, raw); err == nil {
			t.Errorf("expected %s to be rejected", raw)
		}
	}
}

func TestCheckIPNotPrivate_AllowsPublicIP(t *testing.T) {
	ip := net.ParseIP("8.8.8.8")
	if err := checkIPNotPrivate(ip, "8.8.8.8"); err != nil {
		t.Fatalf("expected public IP to be allowed, got %v", err)
	}
}

// --- Rate limiter ---

func TestRateLimiter_Unlimited(t *testing.T) {
	rl := NewRateLimiter(0, 0)
	ctx := context.Background()
	// Should never block.
	for i := 0; i < 10; i++ {
		if err := rl.Wait(ctx); err != nil {
			t.Fatalf("unlimited Wait returned error: %v", err)
		}
	}
}

func TestRateLimiter_ContextCancelled(t *testing.T) {
	// 1 rps limiter — first call consumes the token, second must wait.
	rl := NewRateLimiter(1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	// Drain the initial token.
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("first Wait: %v", err)
	}
	// Cancel immediately so the next Wait returns early.
	cancel()
	err := rl.Wait(ctx)
	if err == nil {
		t.Error("expected context cancellation error from second Wait, got nil")
	}
}

func TestRateLimiter_FixedDelay(t *testing.T) {
	rl := NewRateLimiter(0, 10*time.Millisecond)
	start := time.Now()
	ctx := context.Background()
	if err := rl.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
		t.Errorf("expected at least 10ms delay, got %v", elapsed)
	}
}

func TestRateLimiter_DelayContextCancelled(t *testing.T) {
	rl := NewRateLimiter(0, 5*time.Second) // huge delay
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	err := rl.Wait(ctx)
	if err == nil {
		t.Error("expected context cancellation error during delay, got nil")
	}
}

func TestClient_PostJSON(t *testing.T) {
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	c := NewClientWithLocalNetworkAllowed(true)
	resp, err := c.PostJSON(context.Background(), srv.URL, `{"name":"test"}`, nil)
	if err != nil {
		t.Fatalf("PostJSON: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", gotCT)
	}
	if string(gotBody) != `{"name":"test"}` {
		t.Errorf("body: want {\"name\":\"test\"}, got %q", gotBody)
	}
}

func TestClient_PostJSON_ExtraHeaders(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := NewClientWithLocalNetworkAllowed(true)
	_, err := c.PostJSON(context.Background(), srv.URL, `{}`, map[string]string{
		"Authorization": "Bearer tok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization header: want %q, got %q", "Bearer tok", gotAuth)
	}
}

func TestClient_WithRateLimiter(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	limiter := NewRateLimiter(0, 0) // unlimited, no delay — just verify no crash
	c := NewClientWithLocalNetworkAllowed(true).WithRateLimiter(limiter)
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("Get with limiter: %v", err)
	}
}
