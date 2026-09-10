// Package notify — fanout.go: Discord + Telegram senders and multi-target
// fan-out (Wave 4 item 148). Slack and generic webhooks live in
// webhook.go; this file adds Discord webhook embeds and Telegram
// Bot-API messages. All delivery is best-effort with errors returned
// (callers log and continue). No credentials are stored — tokens and
// chat IDs arrive as operator flags per invocation.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anpu-project/anpu/internal/diff"
)

// summaryText renders one plain-text diff summary for chat targets.
func summaryText(result *diff.Result) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ANPU watch — %s\nRisk: %.1f → %.1f (Δ %+.1f)\n",
		result.Target, result.RiskBefore, result.RiskAfter, result.RiskDelta)
	if result.FindingsAdded > 0 {
		fmt.Fprintf(&sb, "%d new finding(s)\n", result.FindingsAdded)
		for _, fc := range result.Findings {
			if fc.Kind == "added" {
				fmt.Fprintf(&sb, "- [%s/%s] %s\n", fc.Finding.Severity, fc.Finding.Confidence, fc.Finding.Title)
			}
		}
	}
	if result.FindingsRemoved > 0 {
		fmt.Fprintf(&sb, "%d finding(s) resolved\n", result.FindingsRemoved)
	}
	if result.EndpointsAdded > 0 {
		fmt.Fprintf(&sb, "%d new endpoint(s)\n", result.EndpointsAdded)
	}
	if result.FindingsAdded == 0 && result.FindingsChanged == 0 &&
		result.FindingsRemoved == 0 && result.EndpointsAdded == 0 {
		sb.WriteString("No changes detected\n")
	}
	return sb.String()
}

// SendDiscord posts the diff to a Discord incoming webhook.
func SendDiscord(ctx context.Context, webhookURL string, result *diff.Result) error {
	body, err := json.Marshal(map[string]string{"content": summaryText(result)})
	if err != nil {
		return fmt.Errorf("building discord payload: %w", err)
	}
	return postJSON(ctx, webhookURL, body, "discord")
}

// telegramAPIBase is overridable in tests.
var telegramAPIBase = "https://api.telegram.org"

// SendTelegram posts the diff via the Bot API. botToken and chatID come
// from operator flags (ANPU never stores them).
func SendTelegram(ctx context.Context, botToken, chatID string, result *diff.Result) error {
	if strings.TrimSpace(botToken) == "" || strings.TrimSpace(chatID) == "" {
		return fmt.Errorf("telegram needs a bot token and chat id")
	}
	endpoint := telegramAPIBase + "/bot" + botToken + "/sendMessage"
	form := url.Values{"chat_id": {chatID}, "text": {summaryText(result)}}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("creating telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "anpu-watch/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending telegram: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func postJSON(ctx context.Context, webhookURL string, body []byte, who string) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating %s request: %w", who, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "anpu-watch/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending %s: %w", who, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned HTTP %d", who, resp.StatusCode)
	}
	return nil
}

// Targets selects fan-out destinations for one watch iteration.
type Targets struct {
	Webhook  string // Slack or generic (webhook.go Send, auto-detected)
	Discord  string // Discord webhook URL
	Telegram string // "botToken:chatID"
}

// Fanout delivers result to every configured target, collecting errors
// without short-circuiting (one down channel never blocks the others).
func Fanout(ctx context.Context, t Targets, result *diff.Result, on On) []error {
	if !ShouldNotify(result, on) {
		return nil
	}
	var errs []error
	if t.Webhook != "" {
		if err := Send(ctx, t.Webhook, result); err != nil {
			errs = append(errs, err)
		}
	}
	if t.Discord != "" {
		if err := SendDiscord(ctx, t.Discord, result); err != nil {
			errs = append(errs, err)
		}
	}
	if t.Telegram != "" {
		parts := strings.SplitN(t.Telegram, ":", 2)
		if len(parts) != 2 {
			errs = append(errs, fmt.Errorf("invalid --telegram %q: want botToken:chatID", t.Telegram))
		} else if err := SendTelegram(ctx, parts[0], parts[1], result); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
