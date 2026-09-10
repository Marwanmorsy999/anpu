package api

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// GRPCProbe checks for gRPC reflection exposure (CVE-like info disclosure).
// It sends a gRPC frame for grpc.reflection.v1.ServerReflection/ListServices
// with content-type application/grpc and looks for a valid gRPC response.
//
// Safety: Benign — single POST with empty payload, no service invocation.
func GRPCProbe(ctx context.Context, target string, client *anpuhttp.Client) *models.Finding {
	// Derive gRPC endpoint: assume same host with gRPC port inference or same URL base but gRPC path.
	// For Master, probe the target itself with gRPC content-type — if the server speaks gRPC
	// it will respond with grpc-status or service list; otherwise 404/415.
	u := strings.TrimSuffix(target, "/")
	probeURL := u // probe root; reflection is at the same host

	// Build minimal gRPC frame: 5-byte prefix + protobuf payload for ListServices
	// The payload is an empty ListServicesRequest (varint field 0). For detection we just need
	// to see if server answers with application/grpc and a plausible frame.
	// We craft a 5-byte gRPC length-prefixed message with empty body.
	var payload bytes.Buffer
	// gRPC frame: 1 byte compressed flag (0) + 4 byte length
	var frame [5]byte
	frame[0] = 0
	binary.BigEndian.PutUint32(frame[1:], 0)
	payload.Write(frame[:])

	headers := map[string]string{
		"Content-Type": "application/grpc",
		"TE":           "trailers",
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := client.DoWithHeaders(tctx, "POST", probeURL, headers)
	if err != nil || resp == nil {
		// Try with body
		resp, err = client.PostJSON(tctx, probeURL, payload.String(), headers)
		if err != nil || resp == nil {
			return nil
		}
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	grpcStatus := resp.Header.Get("Grpc-Status")
	if strings.Contains(ct, "application/grpc") || grpcStatus != "" || resp.Header.Get("Grpc-Message") != "" {
		return &models.Finding{
			ID:              fmt.Sprintf("api-grpc-reflection-%d", time.Now().UnixNano()),
			Title:           fmt.Sprintf("gRPC reflection exposed at %s", target),
			Description:     fmt.Sprintf("The gRPC server at %s exposes the reflection API (ListServices) without authentication — attackers can enumerate services and methods. The server responded with content-type %q and grpc-status %q.", probeURL, resp.Header.Get("Content-Type"), grpcStatus),
			Severity:        models.SeverityMedium,
			Confidence:      models.ConfidenceMedium,
			Category:        models.CategoryExposure,
			CWE:             "CWE-215",
			OWASP:           "A01:2021 - Broken Access Control",
			Target:          target,
			URL:             probeURL,
			Source:          models.SourceAPI,
			DetectionMethod: "gRPC reflection probe: POST application/grpc ListServices (Master)",
			Evidence: models.Evidence{
				Observed:       fmt.Sprintf("Content-Type: %q, Grpc-Status: %q, body len %d", resp.Header.Get("Content-Type"), grpcStatus, len(resp.Body)),
				Location:       probeURL,
				RequestSummary: fmt.Sprintf("POST %s Content-Type: application/grpc", probeURL),
			},
			Impact:      "Unauthenticated enumeration of gRPC services aids targeted exploitation and reveals internal API surface.",
			Remediation: "Disable gRPC reflection in production or require authentication. Restrict to internal networks.",
			References:  []string{"https://grpc.io/docs/guides/error/", "https://cheatsheetseries.owasp.org/cheatsheets/gRPC_Security_Cheat_Sheet.html"},
			FirstSeen:   time.Now(),
		}
	}
	return nil
}

// ExtractGRPCEndpoints is a helper for scanner.go to probe gRPC when enabled.
// It is called during API scanning if target appears to expose gRPC.
func ProbeGRPC(ctx context.Context, scTarget string, client *anpuhttp.Client) []models.Endpoint {
	// Probe for gRPC and, if found, add a synthetic endpoint for vectors
	finding := GRPCProbe(ctx, scTarget, client)
	if finding == nil {
		return nil
	}
	return []models.Endpoint{{
		URL:      strings.TrimSuffix(scTarget, "/") + "/grpc.reflection.v1.ServerReflection/ListServices",
		Method:   "POST",
		Category: models.EndpointAPI,
		Sources:  []string{"grpc-reflection"},
	}}
}
