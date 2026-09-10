package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/pkg/models"
)

// fileUploadRule detects unrestricted file upload via polyglot probing.
// It sends a multipart/form-data request with a benign polyglot (GIF header
// + shell stub) and checks whether the server stores it without validation.
//
// Safety: LowImpact — small polyglot file, no execution, no OOB.
// Adversarial-gated because upload probing touches storage.
type fileUploadRule struct{}

func (r *fileUploadRule) ID() models.ActiveRuleID    { return "file-upload-unrestricted" }
func (r *fileUploadRule) Name() string               { return "Unrestricted File Upload" }
func (r *fileUploadRule) Safety() models.SafetyLevel { return models.SafetyLowImpact }
func (r *fileUploadRule) RequestBudget() int         { return 3 }

func looksLikeUploadEndpoint(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "upload") || strings.Contains(lower, "file") || strings.Contains(lower, "import") || strings.Contains(lower, "attachment")
}

func (r *fileUploadRule) Test(ctx context.Context, client *anpuhttp.Client, v models.InputVector) (models.ActiveRuleResult, error) {
	result := models.ActiveRuleResult{RuleID: r.ID(), Vector: v}
	if !IsAdversarialEnabled() {
		return result, nil
	}
	if !looksLikeUploadEndpoint(v.URL) && v.Kind != models.VectorJSONBody {
		// Only test upload-like endpoints or JSON vectors that may be file metadata
		if v.Kind != models.VectorQueryParam {
			return result, nil
		}
		if !looksLikeUploadEndpoint(v.URL) {
			return result, nil
		}
	}
	// Probe via PostMultipart to /upload-like URL.
	// Ghost mode uses UploadMarker/UploadFileName/UploadPolyglot
	// (no `anpu` substring).
	marker := UploadMarker()
	fileName := UploadFileName()
	desc := "anpu test"
	if GhostEnabled {
		desc = marker + " test"
	}
	params := map[string]string{"description": desc}
	resp, err := client.PostMultipart(ctx, v.URL, params, "file", fileName, UploadPolyglot(), nil)
	result.RequestsMade++
	if err != nil || resp == nil {
		return result, nil
	}
	bodyLower := strings.ToLower(string(resp.Body))
	markerLower := strings.ToLower(marker)
	// Success signals: server reports file saved, path returned, or no rejection
	if resp.StatusCode == 200 && (strings.Contains(bodyLower, markerLower) || strings.Contains(bodyLower, "upload") && strings.Contains(bodyLower, "success") || strings.Contains(bodyLower, ".php") || strings.Contains(bodyLower, "/uploads/")) {
		// Confirm we didn't just echo back the filename without storing — check for storage location
		if strings.Contains(bodyLower, "href") || strings.Contains(bodyLower, "location") || strings.Contains(bodyLower, "path") {
			result.Found = true
			result.Payload = fileName
			result.Evidence = fmt.Sprintf("File upload polyglot accepted (status %d, body contains storage hint %q) — server may allow unrestricted upload of executable content", resp.StatusCode, snippetForEvidence(resp.Body))
			return result, nil
		}
		// Even without explicit path, 200 with no validation error is candidate
		if !strings.Contains(bodyLower, "invalid") && !strings.Contains(bodyLower, "forbidden") && !strings.Contains(bodyLower, "not allowed") {
			result.Found = true
			result.Payload = fileName
			result.Evidence = fmt.Sprintf("File upload polyglot accepted without validation (status %d, len %d) — possible unrestricted upload", resp.StatusCode, len(resp.Body))
			return result, nil
		}
	}
	return result, nil
}

func (r *fileUploadRule) ToFinding(res models.ActiveRuleResult, target string) models.Finding {
	return models.Finding{
		ID:              fmt.Sprintf("active-upload-%d", time.Now().UnixNano()),
		Title:           fmt.Sprintf("Unrestricted file upload at %s", res.Vector.URL),
		Description:     fmt.Sprintf("The upload endpoint at %s accepted a polyglot file %q without rejecting executable content — attackers can upload webshells. Evidence: %s", res.Vector.URL, res.Payload, res.Evidence),
		Severity:        models.SeverityCritical,
		Confidence:      models.ConfidenceMedium,
		Category:        models.CategoryVulnerability,
		CWE:             "CWE-434",
		OWASP:           "A04:2021 - Insecure Design",
		Target:          target,
		URL:             res.Vector.URL,
		Source:          models.SourceActive,
		DetectionMethod: "file upload probe: multipart polyglot (GIF+PHP) via PostMultipart",
		Evidence:        models.Evidence{Observed: res.Evidence, Location: res.Vector.URL, RequestSummary: fmt.Sprintf("POST %s multipart polyglot %q", res.Vector.URL, res.Payload)},
		Impact:          "Attackers can upload and execute arbitrary code if the upload directory is web-accessible, leading to full server compromise.",
		Remediation:     "Validate file type by magic bytes and extension allowlist, randomize stored filenames, store outside webroot, and enforce strict permissions. Scan uploads with antivirus.",
		References:      []string{"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"},
		FirstSeen:       time.Now(),
	}
}
