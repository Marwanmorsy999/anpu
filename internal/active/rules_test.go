package active

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// testClient returns an ANPU HTTP client pointed at a test server with
// local-network restrictions disabled (the test server runs on 127.0.0.1).
func testClient(t *testing.T) *anpuhttp.Client {
	t.Helper()
	return anpuhttp.NewClientWithLocalNetworkAllowed(true)
}

func testVector(serverURL, param, value string) models.InputVector {
	return models.InputVector{
		URL:           serverURL + "?q=safe&" + param + "=" + value,
		Kind:          models.VectorQueryParam,
		Name:          param,
		OriginalValue: value,
	}
}

// --- XSS ---

func TestXSSRule_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("input")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + val + "</body></html>"))
	}))
	defer srv.Close()

	v := testVector(srv.URL, "input", "hello")
	rule := &xssRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected XSS found=true for unescaped reflection")
	}
}

func TestXSSRule_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HTML-encodes the value — safe
		w.Write([]byte("<html>safe</html>"))
	}))
	defer srv.Close()

	v := testVector(srv.URL, "input", "hello")
	rule := &xssRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Error("expected XSS found=false when canary absent from response")
	}
}

// --- SQLi ---

func TestSQLiRule_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("You have an error in your SQL syntax near ''' at line 1"))
	}))
	defer srv.Close()

	v := testVector(srv.URL, "id", "1")
	rule := &sqliRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected SQLi found=true for DB error response")
	}
}

func TestSQLiRule_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":"ok"}`))
	}))
	defer srv.Close()

	v := testVector(srv.URL, "id", "1")
	rule := &sqliRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Error("expected SQLi found=false for clean response")
	}
}

// --- SSTI ---

func TestSSTIRule_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a template engine evaluating the expression.
		w.Write([]byte("Result: 60481729"))
	}))
	defer srv.Close()

	v := testVector(srv.URL, "name", "world")
	rule := &sstiRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected SSTI found=true when arithmetic result in response")
	}
}

// --- Path Traversal ---

func TestPathTraversalRule_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1"))
	}))
	defer srv.Close()

	v := testVector(srv.URL, "file", "index.html")
	rule := &pathTraversalRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected path traversal found=true for /etc/passwd content")
	}
}

// --- CRLF ---

func TestCRLFRule_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate server setting the injected header.
		w.Header().Set("X-Anpu-Crlf-Canary", "detected")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	v := testVector(srv.URL, "lang", "en")
	rule := &crlfRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected CRLF found=true when canary header in response")
	}
}

// --- Open Redirect ---

func TestOpenRedirectRule_NotFound_CleanResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	v := testVector(srv.URL, "next", "/dashboard")
	rule := &openRedirectRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Error("expected open redirect found=false for clean response")
	}
}

// --- ToFinding sanity checks ---

func TestAllRulesToFinding_NonEmpty(t *testing.T) {
	rules := DefaultRegistry().Rules()
	for _, rule := range rules {
		res := models.ActiveRuleResult{
			RuleID:   rule.ID(),
			Payload:  "test-payload",
			Found:    true,
			Evidence: "test evidence",
			Vector: models.InputVector{
				URL:  "https://example.com/page?q=1",
				Kind: models.VectorQueryParam,
				Name: "q",
			},
		}
		f := rule.ToFinding(res, "https://example.com")
		if f.Title == "" {
			t.Errorf("rule %s ToFinding produced empty title", rule.ID())
		}
		if f.Severity == "" {
			t.Errorf("rule %s ToFinding produced empty severity", rule.ID())
		}
		if f.CWE == "" {
			t.Errorf("rule %s ToFinding produced empty CWE", rule.ID())
		}
		if f.Source != models.SourceActive {
			t.Errorf("rule %s ToFinding source = %q, want SourceActive", rule.ID(), f.Source)
		}
	}
}

// --- JSON body injection (VectorJSONBody) ---

func testJSONBodyVector(serverURL, param string) models.InputVector {
	return models.InputVector{
		URL:           serverURL,
		Kind:          models.VectorJSONBody,
		Name:          param,
		OriginalValue: "safe",
	}
}

func TestXSSRule_JSONBody_Found(t *testing.T) {
	// The server parses the JSON body and reflects the value of "comment"
	// directly into an HTML response without escaping — simulating a
	// vulnerable API that renders user input server-side.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		// Reflect the value verbatim — this is the vulnerable behaviour.
		w.Write([]byte("<html><body>" + m["comment"] + "</body></html>"))
	}))
	defer srv.Close()

	v := testJSONBodyVector(srv.URL, "comment")
	rule := &xssRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected XSS found=true when JSON body value is reflected unescaped")
	}
}

func TestXSSRule_JSONBody_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	v := testJSONBodyVector(srv.URL, "comment")
	rule := &xssRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Error("did not expect XSS found=true when body is not reflected")
	}
}

func TestSQLiRule_JSONBody_Found(t *testing.T) {
	// The server parses the JSON body and reflects a DB error when it
	// sees a single quote — simulating a vulnerable SQL query.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if strings.Contains(m["id"], "'") {
			w.Write([]byte("You have an error in your SQL syntax near '1'"))
		} else {
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()

	v := testJSONBodyVector(srv.URL, "id")
	rule := &sqliRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected SQLi found=true when DB error appears after JSON body injection")
	}
}

func TestSQLiRule_JSONBody_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		w.WriteHeader(200)
		w.Write([]byte(`{"result":"ok"}`))
	}))
	defer srv.Close()

	v := testJSONBodyVector(srv.URL, "id")
	rule := &sqliRule{}
	result, err := rule.Test(context.Background(), testClient(t), v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Error("did not expect SQLi found=true on a clean response")
	}
}
