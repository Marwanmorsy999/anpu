package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/feeds"
)

// newFeedsCmd implements `anpu feeds` (Wave 3 refresh + reputation):
// update refreshes the local KEV cache (single keyless JSON);
// check runs keyless URLhaus + ThreatFox reputation for a target.
func newFeedsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feeds",
		Short: "Refresh and query keyless threat-intel feeds",
	}
	cmd.AddCommand(newFeedsUpdateCmd(), newFeedsCheckCmd())
	return cmd
}

func newFeedsUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Refresh the local CISA KEV cache (keyless)",
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := feeds.RefreshKEV(cmd.Context())
			if err != nil {
				return fmt.Errorf("refreshing KEV: %w", err)
			}
			fmt.Printf("KEV cache refreshed: %d entries (%s)\n", n, filepath.Join(feeds.CacheDir(), "kev.json"))
			return nil
		},
	}
}

func newFeedsCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <url>",
		Short: "Check a URL against keyless reputation feeds",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			notes := feeds.Reputation(cmd.Context(), args[0], host)
			if len(notes) == 0 {
				fmt.Println("No reputation hits (or feeds unreachable — fail-silent).")
				return nil
			}
			for _, n := range notes {
				fmt.Printf("[!] %s\n", n)
			}
			return nil
		},
	}
}

// newWordlistsCmd implements `anpu wordlists update` (Wave 3 item 144):
// refresh vendored subsets from SecLists (opt-in, size-capped).
func newWordlistsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wordlists",
		Short: "Manage vendored wordlist subsets",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "update",
		Short: "Refresh vendored subsets from SecLists (opt-in download)",
		RunE: func(cmd *cobra.Command, args []string) error {
			sources := []struct{ url, dest string }{
				{"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt", "wordlists/dirs-40.txt"},
				{"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt", "wordlists/dns-50.txt"},
			}
			for _, s := range sources {
				n, err := fetchCapped(cmd.Context(), s.url, s.dest, 20000, 50)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "anpu: %s: %v (kept vendored copy)\n", s.dest, err)
					continue
				}
				fmt.Printf("Updated %s (%d lines)\n", s.dest, n)
			}
			return nil
		},
	})
	return cmd
}

// fetchCapped downloads url (30s cap, 1MB cap), keeps the first
// maxLines non-empty lines, and writes them to dest. Used only by
// explicit update commands — never during scans.
func fetchCapped(ctx context.Context, url, dest string, maxBytes, maxLines int) (int, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "anpu-wordlists/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)))
	if err != nil {
		return 0, err
	}
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kept = append(kept, line)
		if len(kept) >= maxLines {
			break
		}
	}
	if len(kept) == 0 {
		return 0, fmt.Errorf("no usable lines")
	}
	if err := os.WriteFile(dest, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		return 0, err
	}
	return len(kept), nil
}
