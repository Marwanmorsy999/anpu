package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/headers"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/nosqlexpand"
	"github.com/anpu-project/anpu/internal/scanner"
	"github.com/anpu-project/anpu/internal/storage"
	"github.com/anpu-project/anpu/pkg/models"
)

// verifyVerdict is the outcome of replaying one finding's probes.
type verifyVerdict struct {
	FindingID     string `json:"finding"`
	Title         string `json:"title"`
	Verdict       string `json:"verdict"` // CONFIRMED, REJECTED, or INCONCLUSIVE
	FreshEvidence string `json:"fresh_evidence"`
}

func newVerifyCmd() *cobra.Command {
	var findingID string
	var scanID string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "verify --finding <id>",
		Short: "Re-check one finding with fresh probes",
		Long: `Replay just the probes behind one stored finding with fresh
controls and print CONFIRMED, REJECTED, or INCONCLUSIVE.

Supported detectors today: backup-file exposure (re-fetch the exact URL),
headers posture (re-evaluate the checklist), NoSQL differentials
(re-run the probe set). Anything else reports INCONCLUSIVE with the
recorded evidence for manual review — never a fabricated verdict.

Examples:
  anpu verify --finding backup-file-exposed-123
  anpu verify --finding headers-posture --scan scan-1700000000-1 --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(findingID) == "" {
				return fmt.Errorf("--finding <id> is required (full ID or unique prefix; see anpu show <scan-id> --long)")
			}
			f, err := locateFinding(scanID, findingID)
			if err != nil {
				return err
			}
			v := verifyFinding(cmd.Context(), f)
			if jsonOut {
				enc, _ := json.MarshalIndent(v, "", "  ")
				fmt.Println(string(enc))
				return nil
			}
			fmt.Printf("Finding: %s\n  Title: %s\n  URL: %s\n", v.FindingID, v.Title, findingURL(f))
			fmt.Printf("Recorded: %s\n", oneLineEvidence(f))
			fmt.Printf("Verdict: %s\n  Fresh: %s\n", v.Verdict, v.FreshEvidence)
			return nil
		},
	}

	cmd.Flags().StringVar(&findingID, "finding", "", "finding ID (or unique prefix) to re-check")
	cmd.Flags().StringVar(&scanID, "scan", "", "limit the lookup to this scan ID (default: search recent scans)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the verdict as JSON")
	return cmd
}

// locateFinding resolves a finding by ID or unique prefix, optionally
// scoped to one scan, else across recent history.
func locateFinding(scanID, findingID string) (models.Finding, error) {
	store, err := storage.Open(defaultDBPath())
	if err != nil {
		return models.Finding{}, fmt.Errorf("opening scan history database: %w", err)
	}
	defer func() { _ = store.Close() }()

	if scanID != "" {
		summary, err := store.GetScan(scanID)
		if err != nil {
			return models.Finding{}, err
		}
		return matchFinding(summary.Findings, findingID)
	}
	items, err := store.ListScans(50)
	if err != nil {
		return models.Finding{}, err
	}
	var candidates []models.Finding
	for _, it := range items {
		summary, err := store.GetScan(it.ID)
		if err != nil {
			continue
		}
		for _, f := range summary.Findings {
			if f.ID == findingID || strings.HasPrefix(f.ID, findingID) {
				candidates = append(candidates, f)
			}
		}
	}
	if len(candidates) == 0 {
		return models.Finding{}, fmt.Errorf("finding %q not found in recent scans (try --scan <id>)", findingID)
	}
	if len(candidates) > 1 {
		return models.Finding{}, fmt.Errorf("prefix %q matches %d findings — pass a longer prefix or --scan <id>", findingID, len(candidates))
	}
	return candidates[0], nil
}

func matchFinding(fs []models.Finding, id string) (models.Finding, error) {
	var candidates []models.Finding
	for _, f := range fs {
		if f.ID == id || strings.HasPrefix(f.ID, id) {
			candidates = append(candidates, f)
		}
	}
	if len(candidates) == 0 {
		return models.Finding{}, fmt.Errorf("finding %q not in this scan", id)
	}
	if len(candidates) > 1 {
		return models.Finding{}, fmt.Errorf("prefix %q matches %d findings — pass a longer prefix", id, len(candidates))
	}
	return candidates[0], nil
}

func findingURL(f models.Finding) string {
	if f.URL != "" {
		return f.URL
	}
	return f.Target
}

func oneLineEvidence(f models.Finding) string {
	obs := strings.Join(strings.Fields(f.Evidence.Observed), " ")
	if len(obs) > 220 {
		obs = obs[:220] + "..."
	}
	if obs == "" {
		return "(no recorded evidence)"
	}
	return obs
}

// verifyFinding replays the finding's detector with fresh controls.
func verifyFinding(ctx context.Context, f models.Finding) verifyVerdict {
	v := verifyVerdict{FindingID: f.ID, Title: f.Title}
	client := anpuhttp.NewClient()
	switch {
	case strings.HasPrefix(f.ID, "backup-file-exposed-"):
		v.FreshEvidence, v.Verdict = verifyBackupURL(ctx, client, findingURL(f))
	case f.ID == "headers-posture":
		v.FreshEvidence, v.Verdict = verifyPosture(ctx, client, findingURL(f))
	case strings.HasPrefix(f.ID, "nosqlexpand-"):
		v.FreshEvidence, v.Verdict = verifyNoSQL(ctx, client, f)
	default:
		v.Verdict = "INCONCLUSIVE"
		v.FreshEvidence = fmt.Sprintf("no verifier for detector %q — manual review against the recorded evidence above", f.ID)
	}
	return v
}

// verifyBackupURL re-fetches the exact exposed URL: still serving a
// non-trivial body means the file is still exposed.
func verifyBackupURL(ctx context.Context, client *anpuhttp.Client, rawURL string) (string, string) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := client.Get(cctx, rawURL)
	if err != nil || resp == nil {
		return fmt.Sprintf("re-fetch failed: %v", err), "INCONCLUSIVE"
	}
	evidence := fmt.Sprintf("HTTP %d, %d bytes, Content-Type %q", resp.StatusCode, len(resp.Body), resp.Header.Get("Content-Type"))
	if (resp.StatusCode == 200 || resp.StatusCode == 206) && len(resp.Body) >= 200 {
		return evidence + " — file still served", "CONFIRMED"
	}
	return evidence + " — no longer exposed", "REJECTED"
}

// verifyPosture re-evaluates the header checklist with a fresh fetch.
func verifyPosture(ctx context.Context, client *anpuhttp.Client, targetURL string) (string, string) {
	absent, err := headers.VerifyAbsent(ctx, client, targetURL)
	if err != nil {
		return fmt.Sprintf("re-fetch failed: %v", err), "INCONCLUSIVE"
	}
	if len(absent) == 0 {
		return "all posture headers now present — posture fixed", "REJECTED"
	}
	return fmt.Sprintf("still absent: %s", strings.Join(absent, ", ")), "CONFIRMED"
}

// verifyNoSQL re-runs the differential probe set against the finding URL
// and looks for a same-class (CWE-943) recurrence.
func verifyNoSQL(ctx context.Context, client *anpuhttp.Client, f models.Finding) (string, string) {
	target, err := scanner.ValidateTarget(f.Target)
	if err != nil {
		return fmt.Sprintf("target invalid: %v", err), "INCONCLUSIVE"
	}
	scCtx := &scanner.ScanContext{
		Target:    target,
		Endpoints: []models.Endpoint{{URL: findingURL(f), Category: models.EndpointUnknown}},
	}
	res, err := nosqlexpand.New(client).Run(ctx, scCtx)
	if err != nil {
		return fmt.Sprintf("probe run failed: %v", err), "INCONCLUSIVE"
	}
	for _, nf := range res.Findings {
		if nf.CWE == "CWE-943" {
			return fmt.Sprintf("differential recurs with fresh controls (%s)", oneLineFinding(nf.Title, 160)), "CONFIRMED"
		}
	}
	return "no NoSQL differential recurs with fresh controls", "REJECTED"
}
