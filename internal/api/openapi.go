// Package api implements ANPU's Phase 5 API Security scanner.
//
// It handles:
//   - OpenAPI 3.x and Swagger 2.x schema loading (file path or URL)
//   - GraphQL introspection of a live endpoint
//   - Converting schema operations into ANPU Endpoint + InputVector records
//     so the existing Phase 3 (authz) and Phase 4 (active) engines can
//     probe API surfaces without any changes to those engines.
//
// Design constraints (same as active engine):
//   - Read/GET-only by default; POST injection is schema-gated and explicit.
//   - No credentials in findings or vectors.
//   - Canary values only; no real data is inferred from schemas.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/pkg/models"
	"gopkg.in/yaml.v3"
)

// openAPIDoc is the minimal subset of an OpenAPI 3.x / Swagger 2.x
// document that ANPU needs to enumerate operations and parameters.
// We decode only the fields we use; unknown fields are ignored.
type openAPIDoc struct {
	Swagger  string   `json:"swagger"`            // "2.0"
	OpenAPI  string   `json:"openapi"`            // "3.x.y"
	BasePath string   `json:"basePath,omitempty"` // Swagger 2
	Host     string   `json:"host,omitempty"`     // Swagger 2
	Schemes  []string `json:"schemes,omitempty"`  // Swagger 2

	// OpenAPI 3 servers block
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers,omitempty"`

	Paths map[string]pathItem `json:"paths"`
}

// pathItem maps HTTP verbs to operation objects.
type pathItem struct {
	Get     *operation `json:"get"`
	Post    *operation `json:"post"`
	Put     *operation `json:"put"`
	Patch   *operation `json:"patch"`
	Delete  *operation `json:"delete"`
	Head    *operation `json:"head"`
	Options *operation `json:"options"`
}

type operation struct {
	OperationID string       `json:"operationId"`
	Summary     string       `json:"summary"`
	Description string       `json:"description"`
	Tags        []string     `json:"tags"`
	Parameters  []parameter  `json:"parameters"`
	RequestBody *requestBody `json:"requestBody,omitempty"`
}

type parameter struct {
	Name     string `json:"name"`
	In       string `json:"in"` // query, path, header, cookie, body (swagger 2)
	Required bool   `json:"required"`
	Schema   struct {
		Type    string      `json:"type"`
		Format  string      `json:"format,omitempty"`
		Example interface{} `json:"example,omitempty"`
	} `json:"schema"`
	// Swagger 2 puts type at the parameter level
	Type    string      `json:"type,omitempty"`
	Example interface{} `json:"example,omitempty"`
}

type requestBody struct {
	Required bool `json:"required"`
	Content  map[string]struct {
		Schema struct {
			Type       string                    `json:"type"`
			Properties map[string]propertySchema `json:"properties,omitempty"`
			Example    interface{}               `json:"example,omitempty"`
		} `json:"schema"`
	} `json:"content"`
}

type propertySchema struct {
	Type    string      `json:"type"`
	Format  string      `json:"format,omitempty"`
	Example interface{} `json:"example,omitempty"`
}

// LoadOpenAPI reads an OpenAPI / Swagger document from a local file path
// or an http(s) URL and returns the parsed APIEndpoints.
// baseURL overrides the server base detected from the document; pass ""
// to auto-detect.
func LoadOpenAPI(source string, baseURL string) ([]models.APIEndpoint, error) {
	return LoadOpenAPIWithAuth(context.Background(), source, baseURL, nil, nil)
}

// LoadOpenAPIWithAuth is the auth-aware variant used by the scanner pipeline.
// It forwards parent ctx and authHeaders via anpuhttp (proxy/limiter/local-net
// guards) so private schema URLs requiring Authorization succeed.
func LoadOpenAPIWithAuth(ctx context.Context, source string, baseURL string, authHeaders map[string]string, client *anpuhttp.Client) ([]models.APIEndpoint, error) {
	raw, err := readSource(ctx, source, authHeaders, client)
	if err != nil {
		return nil, fmt.Errorf("openapi: read %q: %w", source, err)
	}
	return parseOpenAPIDocument(raw, source, baseURL)
}

// parseOpenAPIDocument parses an already-fetched OpenAPI / Swagger
// document. It lets callers (e.g. zero-config discovery) validate a
// response body without fetching it twice. JSON is tried first with a
// YAML→JSON pre-pass fallback (openapi.yaml, swagger.yaml).
func parseOpenAPIDocument(raw []byte, source string, baseURL string) ([]models.APIEndpoint, error) {
	var doc openAPIDoc
	if err := json.Unmarshal(raw, &doc); err != nil || (doc.Paths == nil && doc.OpenAPI == "" && doc.Swagger == "") {
		// YAML pre-pass: unmarshal YAML into the same struct, then continue.
		var ydoc openAPIDoc
		if yerr := yaml.Unmarshal(raw, &ydoc); yerr == nil && !(ydoc.Paths == nil && ydoc.OpenAPI == "" && ydoc.Swagger == "") {
			doc = ydoc
		} else if err != nil {
			return nil, fmt.Errorf("openapi: parse JSON/YAML from %q: %w", source, err)
		}
	}

	if doc.Paths == nil && doc.OpenAPI == "" && doc.Swagger == "" {
		return nil, fmt.Errorf("openapi: %q does not appear to be an OpenAPI/Swagger document (no 'openapi', 'swagger', or 'paths' field)", source)
	}

	base := baseURL
	if base == "" {
		base = detectBaseURL(&doc)
	}
	base = strings.TrimSuffix(base, "/")

	sourceLabel := "openapi"
	if strings.HasPrefix(doc.Swagger, "2") {
		sourceLabel = "swagger"
	}

	var out []models.APIEndpoint
	for path, item := range doc.Paths {
		ops := map[string]*operation{
			"GET": item.Get, "POST": item.Post, "PUT": item.Put,
			"PATCH": item.Patch, "DELETE": item.Delete,
			"HEAD": item.Head, "OPTIONS": item.Options,
		}
		for method, op := range ops {
			if op == nil {
				continue
			}
			ep := buildAPIEndpoint(base, path, method, op, sourceLabel)
			out = append(out, ep)
		}
	}
	return out, nil
}

// buildAPIEndpoint converts one OpenAPI operation into an APIEndpoint.
func buildAPIEndpoint(base, path, method string, op *operation, sourceLabel string) models.APIEndpoint {
	// Resolve the concrete URL by filling path params with placeholder values.
	resolvedPath := resolvePath(path)
	fullURL := base + resolvedPath

	ep := models.APIEndpoint{
		URL:          fullURL,
		PathTemplate: path,
		Method:       method,
		OperationID:  op.OperationID,
		Summary:      capped(op.Summary, 120),
		Tags:         op.Tags,
		Source:       sourceLabel,
	}

	for _, p := range op.Parameters {
		param := models.APIParam{
			Name:     p.Name,
			In:       models.APIParamIn(p.In),
			Required: p.Required,
			Schema:   coalesceType(p.Schema.Type, p.Type),
			Example:  exampleString(p.Example, p.Schema.Example, p.Schema.Type, p.Type),
		}
		ep.Params = append(ep.Params, param)
	}

	// Seed query params with example values into the URL (mirroring
	// resolvePath for path params): schema URLs must be realistic
	// requests — gates and rules baseline against ep.URL.
	if qs := seedQuery(ep.Params); qs != "" {
		sep := "?"
		if strings.Contains(fullURL, "?") {
			sep = "&"
		}
		ep.URL = fullURL + sep + qs
	}

	if op.RequestBody != nil {
		for ct, media := range op.RequestBody.Content {
			ep.ContentType = ct
			for propName, prop := range media.Schema.Properties {
				param := models.APIParam{
					Name:    propName,
					In:      models.APIParamInBody,
					Schema:  prop.Type,
					Example: exampleString(prop.Example, nil, prop.Type, ""),
				}
				ep.Params = append(ep.Params, param)
			}
			break // take first content type only
		}
	}

	return ep
}

// seedQuery encodes query-param examples as a query string for URL
// seeding. Only params with a usable example are included.
func seedQuery(params []models.APIParam) string {
	var parts []string
	for _, p := range params {
		if p.In != models.APIParamInQuery || p.Name == "" {
			continue
		}
		val := strings.TrimSpace(p.Example)
		if val == "" {
			continue
		}
		parts = append(parts, url.QueryEscape(p.Name)+"="+url.QueryEscape(val))
	}
	return strings.Join(parts, "&")
}

// detectBaseURL resolves a base URL from an OpenAPI 3 servers block or
// Swagger 2 host/basePath/schemes fields.
func detectBaseURL(doc *openAPIDoc) string {
	if len(doc.Servers) > 0 && doc.Servers[0].URL != "" {
		return doc.Servers[0].URL
	}
	if doc.Host != "" {
		scheme := "https"
		if len(doc.Schemes) > 0 {
			scheme = doc.Schemes[0]
		}
		return scheme + "://" + doc.Host + doc.BasePath
	}
	return ""
}

// resolvePath replaces {param} placeholders with safe placeholder values
// so we produce a probing URL without real data.
func resolvePath(path string) string {
	// Replace every {name} with "1" — enough to build a valid-looking URL.
	var out strings.Builder
	for {
		start := strings.Index(path, "{")
		if start == -1 {
			out.WriteString(path)
			break
		}
		end := strings.Index(path[start:], "}")
		if end == -1 {
			out.WriteString(path)
			break
		}
		out.WriteString(path[:start])
		out.WriteString("1")
		path = path[start+end+1:]
	}
	return out.String()
}

// readSource reads a local file or fetches a URL via anpuhttp
// (redirect guards, proxy, limiter, local-net policy, auth headers).
func readSource(ctx context.Context, source string, authHeaders map[string]string, client *anpuhttp.Client) ([]byte, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		if client == nil {
			client = anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
		}
		if len(authHeaders) > 0 {
			client = client.WithAuth(authHeaders)
		}
		tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		resp, err := client.Get(tctx, source)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("openapi: GET %q status %d", source, resp.StatusCode)
		}
		if len(resp.Body) > 4<<20 {
			return resp.Body[:4<<20], nil
		}
		return resp.Body, nil
	}
	f, err := os.Open(source) // #nosec G304 -- CLI reads operator-specified paths (reports, wordlists, checkpoints, code dir).
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 4<<20))
}

// coalesceType returns the first non-empty type string.
func coalesceType(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// exampleString returns a string representation of the best available
// example value, or a safe placeholder derived from the type.
func exampleString(candidates ...interface{}) string {
	// First two candidates are example values (may be nil), rest are type strings.
	for _, v := range candidates[:2] {
		if v != nil {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case float64:
				return fmt.Sprintf("%v", t)
			case bool:
				return fmt.Sprintf("%v", t)
			}
		}
	}
	// Fall back to a type-based placeholder.
	typ := ""
	for _, v := range candidates[2:] {
		if s, ok := v.(string); ok && s != "" {
			typ = s
			break
		}
	}
	switch typ {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	default:
		return "test"
	}
}

// capped truncates a string to at most n characters.
func capped(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// APIEndpointsToEndpoints converts []APIEndpoint → []models.Endpoint so
// they flow through the existing crawler/authz/active pipeline unchanged.
// GET endpoints are passed directly; non-GET endpoints are included with
// their method set so downstream stages can filter if needed.
// Schema params ride along so the active engine can build JSON vectors.
func APIEndpointsToEndpoints(apiEPs []models.APIEndpoint) []models.Endpoint {
	out := make([]models.Endpoint, 0, len(apiEPs))
	for _, ae := range apiEPs {
		// Validate the URL is parseable before adding.
		if _, err := url.Parse(ae.URL); err != nil {
			continue
		}
		cat := models.EndpointAPI
		out = append(out, models.Endpoint{
			URL:      ae.URL,
			Method:   ae.Method,
			Category: cat,
			Sources:  []string{ae.Source},
			Params:   ae.Params,
		})
	}
	return out
}
