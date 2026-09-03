package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/diff"
	"github.com/anpu-project/anpu/internal/findings"
	"github.com/anpu-project/anpu/internal/notify"
	"github.com/anpu-project/anpu/internal/schedule"
	"github.com/anpu-project/anpu/internal/storage"
	"github.com/anpu-project/anpu/pkg/models"
)

func newWatchCmd() *cobra.Command {
	var (
		interval      time.Duration
		cronExpr      string
		webhookURL    string
		webhookOn     string
		profileStr    string
		failOn        string
		minConfidence string
		jsonOut       bool
	)

	cmd := &cobra.Command{
		Use:   "watch <target>",
		Short: "Continuously scan a target and report only new or changed findings",
		Long: `watch runs repeated scans against a target on a fixed interval and
emits only findings that are new or changed since the previous scan.

The first run establishes a baseline. Every subsequent run diffs against
that baseline, so output stays quiet until something actually changes.

Examples:
  anpu watch https://staging.example.com
  anpu watch https://staging.example.com --interval 1h --min-confidence medium
  anpu watch https://staging.example.com --fail-on high --interval 30m`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			minConf, err := findings.ParseMinConfidence(minConfidence)
			if err != nil {
				return err
			}
			failThreshold, err := parseFailOn(failOn)
			if err != nil {
				return err
			}
			profile := models.Profile(profileStr)
			if !profile.Valid() {
				return fmt.Errorf("invalid --profile %q: must be one of safe, standard, deep", profileStr)
			}
			// Parse optional cron expression.
			var sched *schedule.Schedule
			if cronExpr != "" {
				var cronErr error
				sched, cronErr = schedule.Parse(cronExpr)
				if cronErr != nil {
					return fmt.Errorf("invalid --cron: %w", cronErr)
				}
			}
			// Parse optional webhook-on policy.
			wOn, err := notify.ParseOn(webhookOn)
			if err != nil {
				return err
			}
			return runWatch(cmd.Context(), args[0], profileStr, minConf, failThreshold, interval, sched, webhookURL, wOn, jsonOut)
		},
	}

	cmd.Flags().DurationVar(&interval, "interval", 0, "time between scans (e.g. 30m, 1h, 6h); 0 = run once then exit")
	cmd.Flags().StringVar(&cronExpr, "cron", "", `cron schedule for scans, e.g. "0 * * * *" (hourly); overrides --interval`)
	cmd.Flags().StringVar(&webhookURL, "webhook", "", "URL to POST diff results to after each scan (Slack or generic JSON)")
	cmd.Flags().StringVar(&webhookOn, "webhook-on", "change", "when to send webhook notifications: always, change, finding")
	cmd.Flags().StringVar(&profileStr, "profile", "standard", "scan profile: safe, standard, deep")
	cmd.Flags().StringVar(&failOn, "fail-on", "none", "exit non-zero if a new finding at or above this severity is found")
	cmd.Flags().StringVar(&minConfidence, "min-confidence", "none", "skip findings below this confidence level")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print diff results as JSON instead of the default text format")

	return cmd
}

func runWatch(
	ctx context.Context,
	target, profileStr string,
	minConf models.Confidence,
	failThreshold models.Severity,
	interval time.Duration,
	sched *schedule.Schedule,
	webhookURL string,
	webhookOn notify.On,
	jsonOut bool,
) error {
	store, err := storage.Open(defaultDBPath())
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	iteration := 0
	var exitErr error

	for {
		iteration++
		if interval > 0 {
			fmt.Fprintf(os.Stderr, "[watch] iteration %d — %s\n", iteration, target)
		}

		// Load the previous scan BEFORE running so we get the true baseline
		// (runWatchScan saves the new scan; loading after would return it).
		prev, loadErr := store.LatestScanForTarget(target)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "[watch] warning: could not load previous scan: %v\n", loadErr)
		}

		summary, scanErr := runWatchScan(ctx, target, profileStr, minConf)
		if scanErr != nil {
			// Graceful degradation: log and keep watching.
			fmt.Fprintf(os.Stderr, "[watch] scan error: %v\n", scanErr)
		} else {
			if prev == nil {
				fmt.Printf("[watch] baseline established (%d finding(s), risk %.1f/10)\n",
					len(summary.Findings), summary.RiskScore)
			} else {
				result := diff.Compare(prev, summary)
				if jsonOut {
					if b, e := json.Marshal(result); e == nil {
						fmt.Println(string(b))
					}
				} else {
					printWatchDiff(result)
				}
				if failThreshold != "" && watchHasSeverityAtOrAbove(result, failThreshold) {
					exitErr = fmt.Errorf("new finding at or above %s severity", failThreshold)
				}
			}
		}

		// Webhook notification (best-effort).
		if webhookURL != "" && summary != nil && prev != nil {
			wResult := diff.Compare(prev, summary)
			if notify.ShouldNotify(wResult, webhookOn) {
				if wErr := notify.Send(ctx, webhookURL, wResult); wErr != nil {
					fmt.Fprintf(os.Stderr, "[watch] webhook error: %v\n", wErr)
				}
			}
		}

		// Determine wait duration: cron takes priority over --interval.
		var waitDur time.Duration
		if sched != nil {
			waitDur = time.Until(sched.Next(time.Now()))
		} else if interval > 0 {
			waitDur = interval
		} else {
			break // one-shot mode
		}

		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "[watch] stopped")
			return exitErr
		case <-time.After(waitDur):
		}
	}

	return exitErr
}

// runWatchScan runs a full scan by delegating to the existing scan subcommand,
// then loads the persisted result from storage. The scan subcommand saves its
// result automatically; we just read the latest scan for the target after it
// completes.
func runWatchScan(ctx context.Context, target, profileStr string, minConf models.Confidence) (*models.ScanSummary, error) {
	scanCmd := newScanCmd()
	scanArgs := []string{target, "--profile", profileStr}
	if minConf != "" {
		scanArgs = append(scanArgs, "--min-confidence", string(minConf))
	}
	scanCmd.SetArgs(scanArgs)
	scanCmd.SilenceUsage = true
	scanCmd.SilenceErrors = true

	if err := scanCmd.ExecuteContext(ctx); err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	store, err := storage.Open(defaultDBPath())
	if err != nil {
		return nil, fmt.Errorf("opening storage to load result: %w", err)
	}
	defer store.Close()

	summary, err := store.LatestScanForTarget(target)
	if err != nil {
		return nil, fmt.Errorf("loading scan result: %w", err)
	}
	if summary == nil {
		return nil, fmt.Errorf("scan completed but no result found in storage for %q", target)
	}
	return summary, nil
}

func printWatchDiff(result *diff.Result) {
	noChanges := result.FindingsAdded == 0 && result.FindingsChanged == 0 &&
		result.FindingsRemoved == 0 && result.EndpointsAdded == 0 && result.TechnologiesAdded == 0

	if noChanges {
		fmt.Printf("[watch] no changes — %s\n", result.Summary())
		return
	}

	fmt.Printf("\n[watch] changes detected — %s\n\n", result.Summary())

	for _, fc := range result.Findings {
		switch fc.Kind {
		case "added":
			fmt.Printf("  + NEW     %-8s  %-9s  %s\n",
				fc.Finding.Severity, fc.Finding.Confidence, fc.Finding.Title)
			if fc.Finding.URL != "" {
				fmt.Printf("            %s\n", fc.Finding.URL)
			}
		case "changed":
			fmt.Printf("  ~ CHANGED %-8s  %-9s  %s\n",
				fc.Finding.Severity, fc.Finding.Confidence, fc.Finding.Title)
		case "removed":
			fmt.Printf("  - FIXED   %s\n", fc.Finding.Title)
		}
	}

	if result.EndpointsAdded > 0 {
		fmt.Printf("\n  %d new endpoint(s):\n", result.EndpointsAdded)
		for _, ec := range result.Endpoints {
			if ec.Kind == "added" {
				fmt.Printf("    + %s\n", ec.Endpoint.URL)
			}
		}
	}

	if result.TechnologiesAdded > 0 {
		fmt.Printf("\n  %d new technology detected:\n", result.TechnologiesAdded)
		for _, tc := range result.Technologies {
			if tc.Kind == "added" {
				fmt.Printf("    + %s %s\n", tc.Technology.Name, tc.Technology.Version)
			}
		}
	}

	fmt.Println()
}

// watchHasSeverityAtOrAbove reports whether any newly added finding
// meets or exceeds the given severity threshold.
func watchHasSeverityAtOrAbove(result *diff.Result, threshold models.Severity) bool {
	for _, fc := range result.Findings {
		if fc.Kind == "added" && fc.Finding.Severity.Rank() >= threshold.Rank() {
			return true
		}
	}
	return false
}
