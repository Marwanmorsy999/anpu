// Package notify sends watch diff results to external endpoints via webhook.
//
// Two payload modes are supported, auto-detected from the webhook URL:
//   - Slack incoming webhook (url contains "hooks.slack.com") — sends a
//     formatted Slack message block.
//   - Generic webhook — POSTs the raw diff.Result JSON.
//
// Delivery is best-effort: errors are returned to the caller (watch loop)
// which logs and continues — consistent with the graceful-degradation rule.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/diff"
)

// On controls which diff events trigger a notification.
type On string

const (
	// OnAlways fires after every scan, even when there are no changes.
	OnAlways On = "always"
	// OnChange fires whenever any finding, endpoint, or technology changed.
	OnChange On = "change"
	// OnFinding fires only when new findings were added.
	OnFinding On = "finding"
)

// ParseOn validates and returns an On value.
func ParseOn(s string) (On, error) {
	switch On(strings.ToLower(s)) {
	case OnAlways, OnChange, OnFinding:
		return On(strings.ToLower(s)), nil
	case "":
		return OnChange, nil
	}
	return "", fmt.Errorf("invalid --webhook-on %q: must be always, change, or finding", s)
}

// ShouldNotify reports whether a diff result warrants sending a notification
// under the given On policy.
func ShouldNotify(result *diff.Result, on On) bool {
	switch on {
	case OnAlways:
		return true
	case OnChange:
		return result.FindingsAdded > 0 || result.FindingsChanged > 0 ||
			result.FindingsRemoved > 0 || result.EndpointsAdded > 0 ||
			result.TechnologiesAdded > 0
	case OnFinding:
		return result.FindingsAdded > 0
	}
	return false
}

// Send posts the diff result to the configured webhook URL.
// It auto-detects Slack vs generic based on the URL.
func Send(ctx context.Context, webhookURL string, result *diff.Result) error {
	var body []byte
	var err error

	if strings.Contains(webhookURL, "hooks.slack.com") {
		body, err = slackPayload(result)
	} else {
		body, err = genericPayload(result)
	}
	if err != nil {
		return fmt.Errorf("building webhook payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "anpu-watch/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// genericPayload wraps the diff result in a small envelope with metadata.
func genericPayload(result *diff.Result) ([]byte, error) {
	envelope := struct {
		Source    string       `json:"source"`
		Timestamp string       `json:"timestamp"`
		Result    *diff.Result `json:"result"`
	}{
		Source:    "anpu-watch",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Result:    result,
	}
	return json.Marshal(envelope)
}

// slackPayload builds a Slack Block Kit message summarising the diff.
func slackPayload(result *diff.Result) ([]byte, error) {
	emoji := ":white_check_mark:"
	if result.FindingsAdded > 0 {
		emoji = ":rotating_light:"
	} else if result.FindingsChanged > 0 || result.EndpointsAdded > 0 {
		emoji = ":warning:"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s *ANPU watch — %s*\n", emoji, result.Target))
	sb.WriteString(fmt.Sprintf("Risk: %.1f → %.1f  (Δ %+.1f)\n",
		result.RiskBefore, result.RiskAfter, result.RiskDelta))

	if result.FindingsAdded > 0 {
		sb.WriteString(fmt.Sprintf("• %d new finding(s)\n", result.FindingsAdded))
		for _, fc := range result.Findings {
			if fc.Kind == "added" {
				sb.WriteString(fmt.Sprintf("  `%s` %s — %s\n",
					fc.Finding.Severity, fc.Finding.Confidence, fc.Finding.Title))
			}
		}
	}
	if result.FindingsRemoved > 0 {
		sb.WriteString(fmt.Sprintf("• %d finding(s) resolved\n", result.FindingsRemoved))
	}
	if result.EndpointsAdded > 0 {
		sb.WriteString(fmt.Sprintf("• %d new endpoint(s)\n", result.EndpointsAdded))
	}
	if result.FindingsAdded == 0 && result.FindingsChanged == 0 &&
		result.FindingsRemoved == 0 && result.EndpointsAdded == 0 {
		sb.WriteString("• No changes detected\n")
	}

	payload := map[string]any{
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": sb.String(),
				},
			},
		},
	}
	return json.Marshal(payload)
}
