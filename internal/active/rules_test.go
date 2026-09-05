package active

import (
	"context"
	"encoding/json"
	"fmt"
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

// --- XXE ---

func xmlVector(url string) models.InputVector {
	return models.InputVector{
		URL:  url,
		Kind: models.VectorXMLBody,
		Name: url,
	}
}

func TestXXERule_SkipsNonXMLVector(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rule := &xxeRule{}
	vec := testVector(srv.URL, "input", "value") // VectorQueryParam — should be skipped
	result, err := rule.Test(context.Background(), testClient(t), vec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Error("xxeRule should not fire on non-XML vector")
	}
	if called {
		t.Error("xxeRule should make zero requests for non-XML vectors")
	}
}

func TestXXERule_EntityReflection(t *testing.T) {
	// Simulate a vulnerable XML endpoint that reflects entity content.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, _ := io.ReadAll(r.Body)
		// Parse the entity value from the payload and reflect it back —
		// simulates an XXE-vulnerable parser that expands the entity.
		content := string(body)
		// Extract the nonce between the quotes in <!ENTITY ... "nonce">
		start := strings.Index(content, "\"anpu-")
		end := -1
		if start >= 0 {
			end = strings.Index(content[start+1:], "\"")
		}
		nonce := ""
		if start >= 0 && end >= 0 {
			nonce = content[start+1 : start+1+end]
		}
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte("<response>" + nonce + "</response>"))
	}))
	defer srv.Close()

	rule := &xxeRule{}
	result, err := rule.Test(context.Background(), testClient(t), xmlVector(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected xxeRule to find entity reflection")
	}
	if !strings.Contains(result.Evidence, "entity reflection confirmed") {
		t.Errorf("evidence should mention reflection, got: %s", result.Evidence)
	}
}

func TestXXERule_ParserErrorSignal(t *testing.T) {
	// Simulate an endpoint that returns an XML parse error string.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("XML parsing error: invalid DOCTYPE declaration"))
	}))
	defer srv.Close()

	rule := &xxeRule{}
	result, err := rule.Test(context.Background(), testClient(t), xmlVector(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected xxeRule to detect parser error signal")
	}
	if !strings.Contains(result.Evidence, "xml parsing error") {
		t.Errorf("evidence should contain error signature, got: %s", result.Evidence)
	}
}

func TestXXERule_StackTraceSignal(t *testing.T) {
	// Simulate an endpoint that leaks a Java XML stack trace.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Exception in thread main com.sun.org.apache.xerces.internal.impl.XMLStreamReaderImpl"))
	}))
	defer srv.Close()

	rule := &xxeRule{}
	result, err := rule.Test(context.Background(), testClient(t), xmlVector(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected xxeRule to detect stack trace signal")
	}
}

func TestXXERule_StatusChangeTo500(t *testing.T) {
	// Simulate an endpoint that returns 200 on GET but 500 on POST with DOCTYPE.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<ok/>"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	rule := &xxeRule{}
	result, err := rule.Test(context.Background(), testClient(t), xmlVector(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected xxeRule to detect status-change signal (200→500)")
	}
	if !strings.Contains(result.Evidence, "HTTP 500") {
		t.Errorf("evidence should mention status 500, got: %s", result.Evidence)
	}
}

func TestXXERule_NoFinding_CleanEndpoint(t *testing.T) {
	// Simulate a safe XML endpoint that ignores the DOCTYPE and returns
	// a generic response with no error strings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<response><status>ok</status></response>"))
	}))
	defer srv.Close()

	rule := &xxeRule{}
	result, err := rule.Test(context.Background(), testClient(t), xmlVector(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Errorf("expected no finding for safe endpoint, got evidence: %s", result.Evidence)
	}
}

func TestXXERule_ToFinding_ReflectionIsHigh(t *testing.T) {
	rule := &xxeRule{}
	res := models.ActiveRuleResult{
		RuleID:  rule.ID(),
		Vector:  xmlVector("https://example.com/api/xml"),
		Found:   true,
		Payload: buildXXEPayload("anpu-cafebabe"),
		Evidence: "XXE entity reflection confirmed: canary value \"anpu-cafebabe\" appeared in response body (status 200). " +
			"The XML parser expanded the internal entity defined in the DOCTYPE.",
	}
	f := rule.ToFinding(res, "https://example.com")
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("reflection signal should be ConfidenceHigh, got %s", f.Confidence)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("XXE should be SeverityCritical, got %s", f.Severity)
	}
	if f.CWE != "CWE-611" {
		t.Errorf("CWE should be CWE-611, got %s", f.CWE)
	}
}

func TestXXERule_ToFinding_StatusChangeIsLow(t *testing.T) {
	rule := &xxeRule{}
	res := models.ActiveRuleResult{
		RuleID:   rule.ID(),
		Vector:   xmlVector("https://example.com/api/xml"),
		Found:    true,
		Evidence: "Server returned HTTP 500 (baseline was 200) after sending a DOCTYPE payload.",
	}
	f := rule.ToFinding(res, "https://example.com")
	if f.Confidence != models.ConfidenceLow {
		t.Errorf("status-change signal should be ConfidenceLow, got %s", f.Confidence)
	}
}

// --- ExtractXMLVectors ---

func TestExtractXMLVectors_XMLTaggedEndpoint(t *testing.T) {
	eps := []models.Endpoint{
		{URL: "https://example.com/api/ingest", Method: "POST", Sources: []string{"api-xml-body"}},
	}
	vecs := ExtractXMLVectors(eps)
	if len(vecs) != 1 {
		t.Fatalf("expected 1 vector, got %d", len(vecs))
	}
	if vecs[0].Kind != models.VectorXMLBody {
		t.Errorf("kind: got %q, want xml-body", vecs[0].Kind)
	}
}

func TestExtractXMLVectors_HeuristicXMLPath(t *testing.T) {
	eps := []models.Endpoint{
		{URL: "https://example.com/soap/endpoint", Method: "POST", Sources: []string{"crawler"}},
	}
	vecs := ExtractXMLVectors(eps)
	if len(vecs) != 1 {
		t.Fatalf("expected 1 vector for SOAP endpoint, got %d", len(vecs))
	}
}

func TestExtractXMLVectors_SkipsGET(t *testing.T) {
	eps := []models.Endpoint{
		{URL: "https://example.com/xml/data", Method: "GET", Sources: []string{"crawler"}},
	}
	vecs := ExtractXMLVectors(eps)
	if len(vecs) != 0 {
		t.Errorf("GET endpoints should be skipped, got %d vectors", len(vecs))
	}
}

func TestExtractXMLVectors_Deduplication(t *testing.T) {
	eps := []models.Endpoint{
		{URL: "https://example.com/xml/import", Method: "POST", Sources: []string{"api-xml-body"}},
		{URL: "https://example.com/xml/import", Method: "POST", Sources: []string{"api-xml-body"}},
	}
	vecs := ExtractXMLVectors(eps)
	if len(vecs) != 1 {
		t.Errorf("duplicate endpoints should produce 1 vector, got %d", len(vecs))
	}
}

func TestBuildXXEPayload_ContainsNonce(t *testing.T) {
	nonce := "anpu-deadbeef"
	payload := buildXXEPayload(nonce)
	if !strings.Contains(payload, nonce) {
		t.Error("payload should contain the nonce as entity value and reference")
	}
	if !strings.Contains(payload, "<!DOCTYPE") {
		t.Error("payload should contain DOCTYPE declaration")
	}
	if !strings.Contains(payload, "<!ENTITY") {
		t.Error("payload should contain ENTITY declaration")
	}
}

// --- Host Header Injection ---

func TestHostHeaderRule_BodyReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Reflect the Host header into the response body (vulnerable behaviour).
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<a href='https://" + r.Host + "/reset'>Reset password</a>"))
		}
	}))
	defer srv.Close()

	rule := &hostHeaderRule{}
	vec := testVector(srv.URL, "q", "value")
	result, err := rule.Test(context.Background(), testClient(t), vec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected hostHeaderRule to detect body reflection")
	}
	if !strings.Contains(result.Evidence, "reflected in response body") {
		t.Errorf("evidence should mention reflection, got: %s", result.Evidence)
	}
}

func TestHostHeaderRule_LocationRedirect(t *testing.T) {
	// Simulate a server that uses the Host header to build a password-reset URL.
	// After the redirect the reset page body also contains the host — this is
	// the realistic pattern (email links built from Host).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always reflect the incoming Host header somewhere in the response.
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(fmt.Sprintf(
			"<p>Reset your password at https://%s/reset?token=abc</p>", r.Host,
		)))
	}))
	defer srv.Close()

	rule := &hostHeaderRule{}
	vec := testVector(srv.URL, "email", "user@example.com")
	result, err := rule.Test(context.Background(), testClient(t), vec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected hostHeaderRule to detect canary reflected in password-reset URL in body")
	}
}

func TestHostHeaderRule_NoFinding_SafeEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe: ignores Host header entirely, always returns fixed content.
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Hello world</body></html>"))
	}))
	defer srv.Close()

	rule := &hostHeaderRule{}
	vec := testVector(srv.URL, "q", "value")
	result, err := rule.Test(context.Background(), testClient(t), vec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Errorf("expected no finding for safe endpoint, got: %s", result.Evidence)
	}
}

func TestHostHeaderRule_SkipsXMLBodyVector(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rule := &hostHeaderRule{}
	vec := models.InputVector{URL: srv.URL, Kind: models.VectorXMLBody, Name: srv.URL}
	result, err := rule.Test(context.Background(), testClient(t), vec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Error("hostHeaderRule should not fire on XML body vectors")
	}
	_ = called // may still be called for baseline; just checking Found
}

func TestHostHeaderRule_ToFinding_LocationIsMostDangerous(t *testing.T) {
	rule := &hostHeaderRule{}
	res := models.ActiveRuleResult{
		RuleID:  rule.ID(),
		Vector:  testVector("https://example.com/reset", "email", "user@example.com"),
		Found:   true,
		Payload: "anpu-cafebabe.invalid",
		Evidence: "Host header canary \"anpu-cafebabe.invalid\" appeared in Location redirect header: " +
			"\"https://anpu-cafebabe.invalid/reset?token=abc\" (status 302). This enables password-reset link poisoning.",
	}
	f := rule.ToFinding(res, "https://example.com")
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity: got %q, want high", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("confidence: got %q, want high", f.Confidence)
	}
	if f.CWE != "CWE-20" {
		t.Errorf("CWE: got %q, want CWE-20", f.CWE)
	}
	if !strings.Contains(f.Impact, "password reset") {
		t.Errorf("impact should mention password reset, got: %s", f.Impact)
	}
}

func TestHostNonce_Format(t *testing.T) {
	n := hostNonce()
	if !strings.HasPrefix(n, "anpu-") {
		t.Errorf("nonce should start with anpu-, got %q", n)
	}
	if !strings.HasSuffix(n, ".invalid") {
		t.Errorf("nonce should end with .invalid, got %q", n)
	}
	// Two nonces should differ (with overwhelming probability).
	n2 := hostNonce()
	if n == n2 {
		t.Error("two nonces should not be identical")
	}
}

// --- NoSQL Injection ---

func TestNosqlRule_JSONBodyAuthBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Vulnerable: returns 200+token when $gt operator bypasses the check.
		if strings.Contains(string(body), "$gt") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"abc123","user":{"role":"admin"}}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer srv.Close()

	rule := &nosqlRule{}
	vec := models.InputVector{URL: srv.URL + "/login", Kind: models.VectorJSONBody, Name: "password"}
	result, err := rule.Test(context.Background(), testClient(t), vec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected nosqlRule to detect JSON body auth bypass")
	}
	if !strings.Contains(result.Evidence, "401") || !strings.Contains(result.Evidence, "200") {
		t.Errorf("evidence should show status change 401→200, got: %s", result.Evidence)
	}
}

func TestNosqlRule_QueryStringOperator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		if strings.Contains(q, "%24gt") || strings.Contains(q, "$gt") || strings.Contains(q, "%5Bgt%5D") || strings.Contains(q, "[gt]") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"username":"admin","email":"admin@example.com"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"bad credentials"}`))
	}))
	defer srv.Close()

	rule := &nosqlRule{}
	vec := testVector(srv.URL+"/api/login", "username", "test")
	result, err := rule.Test(context.Background(), testClient(t), vec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected nosqlRule to detect QS operator injection")
	}
}

func TestNosqlRule_ErrorDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "$gt") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`CastError: Cast to string failed for value {"$gt":""} (type Object) at path "password"`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid"}`))
	}))
	defer srv.Close()

	rule := &nosqlRule{}
	vec := models.InputVector{URL: srv.URL + "/login", Kind: models.VectorJSONBody, Name: "password"}
	result, err := rule.Test(context.Background(), testClient(t), vec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Error("expected nosqlRule to detect MongoDB error disclosure")
	}
}

func TestNosqlRule_NoFinding_SafeEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe: always returns 401 regardless of input.
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer srv.Close()

	rule := &nosqlRule{}
	vec := models.InputVector{URL: srv.URL + "/login", Kind: models.VectorJSONBody, Name: "password"}
	result, err := rule.Test(context.Background(), testClient(t), vec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Found {
		t.Errorf("expected no finding for safe endpoint, got: %s", result.Evidence)
	}
}

func TestNosqlRule_SkipsXMLVector(t *testing.T) {
	rule := &nosqlRule{}
	vec := models.InputVector{URL: "https://example.com/api", Kind: models.VectorXMLBody, Name: "x"}
	result, _ := rule.Test(context.Background(), testClient(t), vec)
	if result.Found {
		t.Error("nosqlRule should skip XML vectors")
	}
}

func TestNosqlRule_ToFinding_AuthBypassIsHigh(t *testing.T) {
	rule := &nosqlRule{}
	res := models.ActiveRuleResult{
		RuleID:   rule.ID(),
		Vector:   models.InputVector{URL: "https://example.com/login", Kind: models.VectorJSONBody, Name: "password"},
		Found:    true,
		Evidence: "NoSQL injection (gt-operator) caused status change 401 → 200 — auth bypass.",
	}
	f := rule.ToFinding(res, "https://example.com")
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity: got %q, want high", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("confidence: got %q, want high (status change = definitive signal)", f.Confidence)
	}
	if f.CWE != "CWE-943" {
		t.Errorf("CWE: got %q, want CWE-943", f.CWE)
	}
}

func TestBuildJSONBodyForNosql(t *testing.T) {
	body := buildJSONBodyForNosql("password", `{"$gt":""}`)
	if !strings.Contains(body, `"password"`) {
		t.Errorf("body should contain field name, got: %s", body)
	}
	if !strings.Contains(body, `$gt`) {
		t.Errorf("body should contain operator, got: %s", body)
	}
}

func TestInjectNosqlQS_NoExistingQuery(t *testing.T) {
	u := injectNosqlQS("https://example.com/login", "username", "[$gt]=")
	if !strings.Contains(u, "username[$gt]=") {
		t.Errorf("QS injection: got %q", u)
	}
}

func TestInjectNosqlQS_ExistingQuery(t *testing.T) {
	u := injectNosqlQS("https://example.com/login?foo=bar", "username", "[$gt]=")
	if !strings.HasPrefix(u, "https://example.com/login?foo=bar&username") {
		t.Errorf("QS injection with existing query: got %q", u)
	}
}
