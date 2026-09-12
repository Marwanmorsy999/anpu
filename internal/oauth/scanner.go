// Package oauth analyzes OAuth/OIDC discovery surface (Wave 1 item 15):
// /.well-known/openid-configuration, /.well-known/jwks.json, and
// common authorize/token endpoints. At most 6 requests, GET-only. The
// discovery document's endpoints are returned as Endpoints so AuthZ and
// Active can probe them; response_types including implicit/hybrid flow
// is a Low finding (token-in-fragment exposure).
//
// No login is attempted, no credentials are sent, nothing is granted.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/internal/scanner"
	"github.com/Marwanmorsy999/anpu/pkg/models"
)

// maxRequests bounds all HTTP traffic.
const maxRequests = 6

// Scanner implements scanner.Scanner.
type Scanner struct {
	client *anpuhttp.Client
}

// New builds a Scanner.
func New(client *anpuhttp.Client) *Scanner { return &Scanner{client: client} }

// Name implements scanner.Scanner.
func (s *Scanner) Name() string { return "oauthanalyzer" }

// Available implements scanner.Scanner.
func (s *Scanner) Available(_ context.Context) bool { return true }

type discoveryDoc struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	ResponseTypes         []string `json:"response_types_supported"`
	GrantTypes            []string `json:"grant_types_supported"`
}

// Run implements scanner.Scanner.
func (s *Scanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	made := 0
	get := func(path string) *anpuhttp.Response {
		if made >= maxRequests {
			return nil
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		made++
		resp, err := s.client.Get(cctx, strings.TrimSuffix(sc.Target.Raw, "/")+path)
		if err != nil || resp == nil {
			return nil
		}
		return resp
	}

	var findings []models.Finding
	var endpoints []models.Endpoint

	// 1. OIDC discovery document.
	if resp := get("/.well-known/openid-configuration"); resp != nil && resp.StatusCode == 200 && len(resp.Body) > 0 {
		var doc discoveryDoc
		if err := json.Unmarshal(resp.Body, &doc); err == nil && doc.Issuer != "" {
			for _, u := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JwksURI} {
				if strings.HasPrefix(u, "http") {
					endpoints = append(endpoints, models.Endpoint{URL: u, Category: models.EndpointAuth, Sources: []string{"oidc-discovery"}})
				}
			}
			findings = append(findings, models.Finding{
				ID:              "oauthanalyzer-discovery",
				Title:           "OpenID Connect discovery document published",
				Description:     fmt.Sprintf("The issuer %q advertises authorization/token/JWKS endpoints. Review grant types and keep implicit flow disabled for new clients. Endpoints were added to the scan surface. Reproduce: curl -s TARGET/.well-known/openid-configuration.", doc.Issuer),
				Severity:        models.SeverityInfo,
				Confidence:      models.ConfidenceHigh,
				Category:        models.CategoryExposure,
				Target:          sc.Target.Raw,
				URL:             strings.TrimSuffix(sc.Target.Raw, "/") + "/.well-known/openid-configuration",
				Evidence:        models.Evidence{Observed: "issuer: " + doc.Issuer, Location: "/.well-known/openid-configuration"},
				Source:          models.SourceRecon,
				DetectionMethod: "OIDC discovery parse (oauthanalyzer)",
			})
			if allowsImplicit(doc.ResponseTypes) {
				findings = append(findings, models.Finding{
					ID:              "oauthanalyzer-implicit",
					Title:           "OIDC provider allows implicit/hybrid flow",
					Description:     "response_types_supported includes token-returning flows, which expose tokens in URL fragments to browser history and referers. Prefer authorization-code + PKCE for all clients. Reproduce: read response_types_supported in the discovery document.",
					Severity:        models.SeverityLow,
					Confidence:      models.ConfidenceHigh,
					Category:        models.CategoryConfiguration,
					CWE:             "CWE-613",
					Target:          sc.Target.Raw,
					URL:             strings.TrimSuffix(sc.Target.Raw, "/") + "/.well-known/openid-configuration",
					Evidence:        models.Evidence{Observed: "response_types_supported: " + strings.Join(doc.ResponseTypes, ", "), Location: "/.well-known/openid-configuration"},
					Source:          models.SourceRecon,
					DetectionMethod: "OIDC response-type analysis (oauthanalyzer)",
					Remediation:     "Disable implicit/hybrid flows; use code + PKCE.",
				})
			}
		}
	}
	// 2. Common OAuth endpoints (presence only, content-matched).
	commons := []struct{ path, marker string }{
		{"/oauth/authorize", "client_id"},
		{"/oauth/token", "grant_type"},
		{"/.well-known/jwks.json", "\"keys\""},
	}
	for _, c := range commons {
		if made >= maxRequests {
			break
		}
		resp := get(c.path)
		if resp == nil || len(resp.Body) == 0 {
			continue
		}
		// Any JSON/error mentioning OAuth markers counts as presence;
		// 4xx still proves the endpoint exists.
		if strings.Contains(strings.ToLower(string(resp.Body)), strings.ToLower(c.marker)) {
			findings = append(findings, models.Finding{
				ID:              "oauthanalyzer-present-" + slug(c.path),
				Title:           fmt.Sprintf("OAuth endpoint present: %s", c.path),
				Description:     fmt.Sprintf("The path %s answers with OAuth-shaped content. Ensure PKCE, exact redirect-URI matching, and short token lifetimes. Reproduce: curl -s TARGET%s.", c.path, c.path),
				Severity:        models.SeverityInfo,
				Confidence:      models.ConfidenceMedium,
				Category:        models.CategoryExposure,
				Target:          sc.Target.Raw,
				URL:             strings.TrimSuffix(sc.Target.Raw, "/") + c.path,
				Evidence:        models.Evidence{Observed: fmt.Sprintf("%d + marker %q", resp.StatusCode, c.marker), Location: c.path},
				Source:          models.SourceRecon,
				DetectionMethod: "OAuth endpoint presence probe (oauthanalyzer, ≤6 requests)",
			})
		}
	}
	return scanner.StageResult{Findings: findings, Endpoints: endpoints}, nil
}

func allowsImplicit(types []string) bool {
	for _, t := range types {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "token" || t == "id_token" || t == "id_token token" || t == "code token" || t == "code id_token" || t == "code id_token token" {
			return true
		}
	}
	return false
}

func slug(path string) string {
	s := strings.ToLower(strings.Trim(path, "/"))
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, "/", "-")
	return s
}
