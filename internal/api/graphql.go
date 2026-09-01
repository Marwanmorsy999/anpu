package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/anpu-project/anpu/pkg/models"
)

// introspectionQuery is the standard GraphQL introspection query used to
// discover the full schema.  We request only the fields ANPU needs.
const introspectionQuery = `{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields(includeDeprecated: false) {
        name
        description
        args {
          name
          type { name kind ofType { name kind } }
          defaultValue
        }
        type { name kind ofType { name kind } }
      }
    }
  }
}`

// introspectionResponse is the minimal decoded shape of a GraphQL
// introspection response.
type introspectionResponse struct {
	Data struct {
		Schema struct {
			QueryType    *struct{ Name string } `json:"queryType"`
			MutationType *struct{ Name string } `json:"mutationType"`
			Types        []gqlType              `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type gqlType struct {
	Name   string     `json:"name"`
	Kind   string     `json:"kind"`
	Fields []gqlField `json:"fields"`
}

type gqlField struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Args        []gqlArg `json:"args"`
	Type        gqlTypeRef `json:"type"`
}

type gqlArg struct {
	Name string     `json:"name"`
	Type gqlTypeRef `json:"type"`
}

type gqlTypeRef struct {
	Name   string     `json:"name"`
	Kind   string     `json:"kind"`
	OfType *gqlTypeRef `json:"ofType"`
}

// IntrospectGraphQL sends an introspection query to endpoint and returns
// the parsed GraphQL schema alongside synthesized APIEndpoints.
//
// endpoint is the full GraphQL endpoint URL (e.g. https://api.example.com/graphql).
// auth is the request headers to inject (from the scan's AuthContext).
// timeout caps the HTTP request; 15 s is a reasonable default.
func IntrospectGraphQL(ctx context.Context, endpoint string, authHeaders map[string]string, timeout time.Duration) (*models.GraphQLSchema, []models.APIEndpoint, error) {
	payload, err := json.Marshal(map[string]string{"query": introspectionQuery})
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range authHeaders {
		req.Header.Set(k, v)
	}

	c := &http.Client{Timeout: timeout}
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("graphql introspect POST: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("graphql introspect read body: %w", err)
	}

	var result introspectionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, nil, fmt.Errorf("graphql introspect parse JSON: %w", err)
	}

	if len(result.Errors) > 0 {
		msgs := make([]string, 0, len(result.Errors))
		for _, e := range result.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, nil, fmt.Errorf("graphql introspect errors: %s", strings.Join(msgs, "; "))
	}

	schema := &models.GraphQLSchema{}
	queryTypeName := ""
	mutationTypeName := ""
	if result.Data.Schema.QueryType != nil {
		queryTypeName = result.Data.Schema.QueryType.Name
	}
	if result.Data.Schema.MutationType != nil {
		mutationTypeName = result.Data.Schema.MutationType.Name
	}

	var apiEndpoints []models.APIEndpoint

	for _, t := range result.Data.Schema.Types {
		// Skip built-in introspection types.
		if strings.HasPrefix(t.Name, "__") {
			continue
		}
		schema.TypeNames = append(schema.TypeNames, t.Name)

		switch t.Name {
		case queryTypeName:
			for _, f := range t.Fields {
				gf := gqlFieldToModel(f)
				schema.QueryFields = append(schema.QueryFields, gf)
				// Synthesize a GET-style API endpoint for each query field.
				// We encode the field name as a query param so active rules
				// can inject into it without knowing GraphQL syntax.
				ep := synthesizeGraphQLEndpoint(endpoint, "query", f)
				apiEndpoints = append(apiEndpoints, ep)
			}
		case mutationTypeName:
			for _, f := range t.Fields {
				gf := gqlFieldToModel(f)
				schema.MutationFields = append(schema.MutationFields, gf)
				// Mutations: recorded as POST endpoints so authz stage can
				// probe them, but active GET-only rules skip non-GET endpoints.
				ep := synthesizeGraphQLEndpoint(endpoint, "mutation", f)
				apiEndpoints = append(apiEndpoints, ep)
			}
		}
	}

	return schema, apiEndpoints, nil
}

// synthesizeGraphQLEndpoint creates a probing APIEndpoint for one GraphQL
// field.  For query fields (read operations) the method is GET (encoded
// as query params); for mutations it is POST.
func synthesizeGraphQLEndpoint(baseURL, operationType string, f gqlField) models.APIEndpoint {
	method := "GET"
	if operationType == "mutation" {
		method = "POST"
	}

	// Build a URL that encodes the operation so active rules can probe it:
	// GET https://api.example.com/graphql?_op=user&id=1
	probeURL := baseURL + "?_gql_op=" + f.Name
	for _, arg := range f.Args {
		probeURL += "&" + arg.Name + "=" + gqlArgPlaceholder(arg.Type)
	}

	ep := models.APIEndpoint{
		URL:          probeURL,
		PathTemplate: "/_graphql/" + operationType + "/" + f.Name,
		Method:       method,
		OperationID:  f.Name,
		Summary:      capped(f.Description, 120),
		Source:       "graphql",
	}
	for _, arg := range f.Args {
		ep.Params = append(ep.Params, models.APIParam{
			Name:     arg.Name,
			In:       models.APIParamInQuery,
			Schema:   resolveGQLTypeName(arg.Type),
			Example:  gqlArgPlaceholder(arg.Type),
			Required: isNonNull(arg.Type),
		})
	}
	return ep
}

func gqlFieldToModel(f gqlField) models.GraphQLField {
	gf := models.GraphQLField{
		Name:        f.Name,
		Description: f.Description,
		TypeName:    resolveGQLTypeName(f.Type),
	}
	for _, a := range f.Args {
		gf.Args = append(gf.Args, models.GraphQLArg{
			Name:     a.Name,
			TypeName: resolveGQLTypeName(a.Type),
			Required: isNonNull(a.Type),
		})
	}
	return gf
}

func resolveGQLTypeName(t gqlTypeRef) string {
	if t.Name != "" {
		return t.Name
	}
	if t.OfType != nil {
		return resolveGQLTypeName(*t.OfType)
	}
	return "unknown"
}

func isNonNull(t gqlTypeRef) bool {
	return t.Kind == "NON_NULL"
}

func gqlArgPlaceholder(t gqlTypeRef) string {
	name := strings.ToLower(resolveGQLTypeName(t))
	switch name {
	case "int", "float", "id":
		return "1"
	case "boolean":
		return "true"
	default:
		return "test"
	}
}

// CheckGraphQLIntrospectionEnabled returns a Finding if the endpoint
// allows unauthenticated introspection — a common misconfiguration in
// production APIs that leaks the full schema to any caller.
func CheckGraphQLIntrospectionEnabled(endpoint string, schema *models.GraphQLSchema) *models.Finding {
	if schema == nil || (len(schema.QueryFields) == 0 && len(schema.MutationFields) == 0) {
		return nil
	}
	f := models.Finding{
		ID:    fmt.Sprintf("graphql-introspection-%d", time.Now().UnixNano()),
		Title: "GraphQL introspection is enabled",
		Description: fmt.Sprintf(
			"The GraphQL endpoint at %s responded to an unauthenticated introspection query and disclosed %d query fields and %d mutation fields. "+
				"Introspection exposes the full API schema to attackers, revealing field names, argument types, and internal data models that are typically not public knowledge.",
			endpoint, len(schema.QueryFields), len(schema.MutationFields),
		),
		Severity:        models.SeverityMedium,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryConfiguration,
		CWE:             "CWE-200",
		OWASP:           "A05:2021 - Security Misconfiguration",
		Target:          endpoint,
		URL:             endpoint,
		Source:          models.SourceAPI,
		DetectionMethod: "GraphQL introspection query — schema returned without authentication",
		Impact:          "An attacker can enumerate the entire API surface, identify sensitive fields, and craft targeted injection or IDOR attacks against specific operations.",
		Remediation:     "Disable introspection in production. Most GraphQL servers support an 'introspection: false' config option. If introspection is needed for tooling, restrict it to authenticated, authorized users only.",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
		},
		FirstSeen: time.Now(),
		Evidence: models.Evidence{
			Observed: fmt.Sprintf("%d query fields, %d mutation fields, %d named types disclosed",
				len(schema.QueryFields), len(schema.MutationFields), len(schema.TypeNames)),
			Location:       endpoint,
			RequestSummary: "POST " + endpoint + " (introspection query)",
		},
	}
	return &f
}
