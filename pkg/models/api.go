package models

// APIParamIn describes where an API parameter is located.
type APIParamIn string

const (
	APIParamInQuery  APIParamIn = "query"
	APIParamInPath   APIParamIn = "path"
	APIParamInHeader APIParamIn = "header"
	APIParamInBody   APIParamIn = "body"
	APIParamInCookie APIParamIn = "cookie"
)

// APIParam describes one parameter of an API endpoint, derived from an
// OpenAPI/Swagger schema or from GraphQL field definitions.
type APIParam struct {
	Name     string     `json:"name"`
	In       APIParamIn `json:"in"`
	Required bool       `json:"required"`
	// Schema is a simplified description of the expected type
	// ("string", "integer", "object", etc.) — not the full JSON Schema tree.
	Schema string `json:"schema,omitempty"`
	// Example is a usable placeholder value for injection.
	// Populated from the schema's "example" field when present.
	Example string `json:"example,omitempty"`
}

// APIEndpoint is a single operation extracted from an OpenAPI schema or
// a GraphQL introspection result.  It extends the lightweight Endpoint
// model with the richer parameter metadata needed for API-aware probing.
type APIEndpoint struct {
	// URL is the fully-resolved URL (base URL + path with no placeholders).
	URL string `json:"url"`
	// PathTemplate is the raw path template from the schema,
	// e.g. "/users/{id}/orders/{orderId}".
	PathTemplate string `json:"path_template"`
	// Method is the HTTP verb declared in the schema (GET, POST, …).
	// Always uppercase.
	Method string `json:"method"`
	// OperationID is the schema's operationId, if present.
	OperationID string `json:"operation_id,omitempty"`
	// Summary is the schema's summary or description field.
	Summary string `json:"summary,omitempty"`
	// Params is the full list of declared parameters for this operation.
	Params []APIParam `json:"params"`
	// ContentType is the declared request body content-type, if any
	// (e.g. "application/json").
	ContentType string `json:"content_type,omitempty"`
	// Tags groups the operation by resource area (from schema tags).
	Tags []string `json:"tags,omitempty"`
	// Source identifies where this endpoint was discovered.
	// Either "openapi", "swagger", or "graphql".
	Source string `json:"source"`
}

// GraphQLField represents one queryable field from a GraphQL type, used
// to build synthetic probe queries during introspection.
type GraphQLField struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Args are the input arguments accepted by this field.
	Args []GraphQLArg `json:"args,omitempty"`
	// TypeName is the return type name.
	TypeName string `json:"type_name"`
}

// GraphQLArg is one argument of a GraphQL field.
type GraphQLArg struct {
	Name     string `json:"name"`
	TypeName string `json:"type_name"`
	Required bool   `json:"required"`
}

// GraphQLSchema is the simplified result of a GraphQL introspection
// request, containing only the data ANPU needs for security testing.
type GraphQLSchema struct {
	// QueryFields are the fields on the root Query type.
	QueryFields []GraphQLField `json:"query_fields,omitempty"`
	// MutationFields are the fields on the root Mutation type.
	MutationFields []GraphQLField `json:"mutation_fields,omitempty"`
	// TypeNames is the full list of named types in the schema,
	// used to detect information disclosure.
	TypeNames []string `json:"type_names,omitempty"`
}
