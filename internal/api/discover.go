package api

import (
	"context"
	"net/url"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
)

// Well-known locations probed (GET-only) when no --openapi/--graphql flag
// was given. Ordered cheapest-first: schema documents before GraphQL
// (introspection is a heavier POST). Budget: 6×3s GET.
var openAPIDiscoveryPaths = []string{
	"/openapi.json",
	"/swagger.json",
	"/openapi.yaml",
	"/swagger.yaml",
	"/v3/api-docs",
	"/api-docs",
}

var graphQLDiscoveryPaths = []string{
	"/graphql",
	"/api/graphql",
	"/graphiql",
}

// joinBase concatenates a host root with a well-known path. Subpath
// targets (https://host/app) resolve to the host root (https://host/path)
// since well-known schema locations live at the root.
func joinBase(base, path string) string {
	if u, err := url.Parse(base); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host + path
	}
	return strings.TrimSuffix(base, "/") + path
}

// looksLikeOpenAPI reports whether a fetched document smells like an
// OpenAPI/Swagger schema without fully parsing it. Accepts JSON
// ("openapi") and YAML (openapi:) forms.
func looksLikeOpenAPI(body []byte, contentType string) bool {
	if len(body) == 0 || len(body) > 4*1024*1024 {
		return false
	}
	lower := strings.ToLower(string(body))
	hasDoc := strings.Contains(lower, `"openapi"`) || strings.Contains(lower, `"swagger"`) ||
		strings.Contains(lower, "openapi:") || strings.Contains(lower, "swagger:")
	if !hasDoc {
		return false
	}
	if ct := strings.ToLower(contentType); ct != "" &&
		!strings.Contains(ct, "json") && !strings.Contains(ct, "text") &&
		!strings.Contains(ct, "yaml") && !strings.Contains(ct, "octet-stream") {
		return false
	}
	return strings.Contains(lower, `"paths"`) || strings.Contains(lower, "paths:")
}

// DiscoverSchemas hunts for API schemas with zero configuration: it
// GETs well-known OpenAPI locations (6×3s) and POSTs GraphQL introspection
// to well-known GraphQL locations (3×5s). It returns the first working
// OpenAPI document URL and/or GraphQL endpoint URL (either may be empty).
// All probes are read-only; total cost is bounded by per-probe timeouts
// plus an overall ≤30s deadline.
func DiscoverSchemas(ctx context.Context, client *anpuhttp.Client, target string) (openAPIURL, graphqlURL string) {
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// --- OpenAPI / Swagger documents (6×3s GET) ---
	for _, p := range openAPIDiscoveryPaths {
		select {
		case <-dctx.Done():
			return openAPIURL, graphqlURL
		default:
		}
		u := joinBase(target, p)
		pctx, pcancel := context.WithTimeout(dctx, 3*time.Second)
		resp, err := client.Get(pctx, u)
		pcancel()
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		ct := ""
		if resp.Header != nil {
			ct = resp.Header.Get("Content-Type")
		}
		if !looksLikeOpenAPI(resp.Body, ct) {
			continue
		}
		// Confirm it parses before claiming it (reuses the fetched
		// body — no second request).
		if _, err := parseOpenAPIDocument(resp.Body, u, ""); err != nil {
			continue
		}
		openAPIURL = u
		break
	}

	// --- GraphQL endpoints (3×5s introspect; POST doubles as the probe) ---
	for _, p := range graphQLDiscoveryPaths {
		select {
		case <-dctx.Done():
			return openAPIURL, graphqlURL
		default:
		}
		u := joinBase(target, p)
		if _, _, err := IntrospectGraphQL(dctx, u, nil, client, 5*time.Second); err == nil {
			graphqlURL = u
			break
		}
	}

	return openAPIURL, graphqlURL
}

// discoveryClient builds the HTTP client used for schema discovery,
// honoring the scanner's local-network policy.
func discoveryClient() *anpuhttp.Client {
	return anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
}
