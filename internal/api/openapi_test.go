package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/anpu-project/anpu/internal/api"
	"github.com/anpu-project/anpu/pkg/models"
)

const minimalOpenAPI3 = `{
  "openapi": "3.0.3",
  "info": {"title": "Test API", "version": "1.0"},
  "servers": [{"url": "https://api.example.com/v1"}],
  "paths": {
    "/users/{id}": {
      "get": {
        "operationId": "getUser",
        "summary": "Get a user by ID",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
          {"name": "expand", "in": "query", "schema": {"type": "string"}}
        ]
      },
      "post": {
        "operationId": "createUser",
        "summary": "Create user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "name": {"type": "string"},
                  "email": {"type": "string"},
                  "age": {"type": "integer"}
                }
              }
            }
          }
        }
      }
    },
    "/health": {
      "get": {
        "operationId": "healthCheck",
        "summary": "Health check"
      }
    }
  }
}`

const minimalSwagger2 = `{
  "swagger": "2.0",
  "info": {"title": "Swagger Test", "version": "1.0"},
  "host": "api.example.com",
  "basePath": "/api",
  "schemes": ["https"],
  "paths": {
    "/items/{id}": {
      "get": {
        "operationId": "getItem",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "type": "integer"}
        ],
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestLoadOpenAPI_File(t *testing.T) {
	path := writeTempFile(t, minimalOpenAPI3)
	eps, err := api.LoadOpenAPI(path, "")
	if err != nil {
		t.Fatalf("LoadOpenAPI: %v", err)
	}
	if len(eps) != 3 {
		t.Errorf("expected 3 endpoints, got %d", len(eps))
	}
	var getUserEP *models.APIEndpoint
	for i := range eps {
		if eps[i].OperationID == "getUser" {
			getUserEP = &eps[i]
		}
	}
	if getUserEP == nil {
		t.Fatal("getUser operation not found")
	}
	if getUserEP.Method != "GET" {
		t.Errorf("expected GET, got %s", getUserEP.Method)
	}
	if want := "https://api.example.com/v1/users/1"; getUserEP.URL != want {
		t.Errorf("URL: want %q, got %q", want, getUserEP.URL)
	}
	if len(getUserEP.Params) != 2 {
		t.Errorf("params: want 2, got %d", len(getUserEP.Params))
	}
}

func TestLoadOpenAPI_URL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(minimalOpenAPI3)) //nolint:errcheck
	}))
	defer srv.Close()

	eps, err := api.LoadOpenAPI(srv.URL+"/schema.json", srv.URL)
	if err != nil {
		t.Fatalf("LoadOpenAPI URL: %v", err)
	}
	if len(eps) == 0 {
		t.Fatal("expected endpoints from URL source")
	}
}

func TestLoadOpenAPI_BodyParams(t *testing.T) {
	path := writeTempFile(t, minimalOpenAPI3)
	eps, err := api.LoadOpenAPI(path, "")
	if err != nil {
		t.Fatal(err)
	}
	var postEP *models.APIEndpoint
	for i := range eps {
		if eps[i].OperationID == "createUser" {
			postEP = &eps[i]
		}
	}
	if postEP == nil {
		t.Fatal("createUser operation not found")
	}
	if postEP.ContentType != "application/json" {
		t.Errorf("content-type: want application/json, got %q", postEP.ContentType)
	}
	if len(postEP.Params) == 0 {
		t.Error("expected body params from requestBody properties")
	}
	for _, p := range postEP.Params {
		if p.In != models.APIParamInBody {
			t.Errorf("param %q: expected In=body, got %q", p.Name, p.In)
		}
	}
}

func TestLoadOpenAPI_InvalidJSON(t *testing.T) {
	path := writeTempFile(t, `not json`)
	_, err := api.LoadOpenAPI(path, "")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadOpenAPI_Swagger2(t *testing.T) {
	path := writeTempFile(t, minimalSwagger2)
	eps, err := api.LoadOpenAPI(path, "")
	if err != nil {
		t.Fatalf("LoadOpenAPI swagger2: %v", err)
	}
	if len(eps) != 1 {
		t.Errorf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].Source != "swagger" {
		t.Errorf("source: want swagger, got %q", eps[0].Source)
	}
}

func TestAPIEndpointsToEndpoints(t *testing.T) {
	path := writeTempFile(t, minimalOpenAPI3)
	apiEPs, err := api.LoadOpenAPI(path, "")
	if err != nil {
		t.Fatal(err)
	}
	endpoints := api.APIEndpointsToEndpoints(apiEPs)
	if len(endpoints) != len(apiEPs) {
		t.Errorf("endpoint count mismatch: %d vs %d", len(endpoints), len(apiEPs))
	}
	for _, ep := range endpoints {
		if ep.Category != models.EndpointAPI {
			t.Errorf("endpoint %s: category should be api, got %q", ep.URL, ep.Category)
		}
	}
}

func TestExtractAPIVectors(t *testing.T) {
	ep := models.APIEndpoint{
		URL:    "https://api.example.com/v1/users/1?expand=profile",
		Method: "GET",
		Source: "openapi",
		Params: []models.APIParam{
			{Name: "id", In: models.APIParamInPath, Schema: "integer", Example: "1"},
			{Name: "expand", In: models.APIParamInQuery, Schema: "string", Example: "profile"},
			{Name: "X-Custom", In: models.APIParamInHeader, Schema: "string"},
			{Name: "Authorization", In: models.APIParamInHeader, Schema: "string"},
		},
	}
	vecs := api.ExtractAPIVectors(ep)

	kinds := map[models.InputVectorKind]int{}
	names := map[string]bool{}
	for _, v := range vecs {
		kinds[v.Kind]++
		names[v.Name] = true
	}

	if kinds[models.VectorPathSegment] != 1 {
		t.Errorf("expected 1 path vector, got %d", kinds[models.VectorPathSegment])
	}
	if kinds[models.VectorQueryParam] != 1 {
		t.Errorf("expected 1 query vector, got %d", kinds[models.VectorQueryParam])
	}
	if kinds[models.VectorHeader] != 1 {
		t.Errorf("expected 1 header vector (X-Custom only), got %d", kinds[models.VectorHeader])
	}
	if names["Authorization"] {
		t.Error("Authorization header should be filtered from vectors")
	}
}

func TestBuildJSONPayload(t *testing.T) {
	params := []models.APIParam{
		{Name: "name", In: models.APIParamInBody, Schema: "string"},
		{Name: "age", In: models.APIParamInBody, Schema: "integer"},
	}
	got, err := api.BuildJSONPayload(params, "name", "injected-value")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("BuildJSONPayload produced invalid JSON: %v — %s", err, got)
	}
	if m["name"] != "injected-value" {
		t.Errorf("name: want injected-value, got %v", m["name"])
	}
	if m["age"] == nil {
		t.Error("age should be present with placeholder")
	}
}

func TestCheckGraphQLIntrospectionEnabled_Nil(t *testing.T) {
	if api.CheckGraphQLIntrospectionEnabled("https://example.com/graphql", nil) != nil {
		t.Error("nil schema should return nil finding")
	}
}

func TestCheckGraphQLIntrospectionEnabled_Empty(t *testing.T) {
	if api.CheckGraphQLIntrospectionEnabled("https://example.com/graphql", &models.GraphQLSchema{}) != nil {
		t.Error("empty schema should return nil finding")
	}
}

func TestCheckGraphQLIntrospectionEnabled_Populated(t *testing.T) {
	schema := &models.GraphQLSchema{
		QueryFields: []models.GraphQLField{{Name: "user", TypeName: "User"}},
	}
	f := api.CheckGraphQLIntrospectionEnabled("https://example.com/graphql", schema)
	if f == nil {
		t.Fatal("expected finding for populated schema")
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("severity: want medium, got %s", f.Severity)
	}
	if f.Source != models.SourceAPI {
		t.Errorf("source: want %q, got %q", models.SourceAPI, f.Source)
	}
}
