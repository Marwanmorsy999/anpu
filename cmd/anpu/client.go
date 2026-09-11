package main

import (
	"fmt"
	"time"

	"github.com/anpu-project/anpu/internal/api"
	anpuhttp "github.com/anpu-project/anpu/internal/http"
	"github.com/anpu-project/anpu/internal/scanner"
)

// client.go — HTTP client + API config construction (Phase 6).
// Extracted verbatim from runScan: transport selection, ghost/stealth
// anonymity modes, proxy wiring, and rate limiting, with the same
// status lines in the same order.

// clientOptions selects transport behavior. Sourced from runScan
// parameters (flags) plus ScanRuntime knobs.
type clientOptions struct {
	customUA     string
	stealth      bool
	randomAgent  bool
	proxyURL     string
	rateLimit    float64
	requestDelay time.Duration
	openAPI      string
	graphQLURL   string
	apiBaseURL   string
	silent       bool
}

// buildClient assembles the scan HTTP client and API config exactly as
// runScan did inline: ghost → UA → proxy → rate limiter.
func buildClient(rt *ScanRuntime, opts clientOptions) (*anpuhttp.Client, api.Config, error) {
	client := anpuhttp.NewClientWithLocalNetworkAllowed(scanner.AllowLocalNetwork)
	if rt.Ghost {
		client = client.WithGhost(true)
		if !opts.silent {
			fmt.Printf("  ghost      : enabled (Chrome131 JA3, h2, GREASE, Pareto 800-3500ms, no-anpu canary")
			if rt.GhostWorkers > 0 {
				fmt.Printf(", %d workers", rt.GhostWorkers)
			}
			if rt.ProxyPool != "" {
				fmt.Printf(", pool %s", rt.ProxyPool)
			}
			fmt.Printf(")\n")
		}
	}
	if opts.customUA != "" {
		client = client.WithCustomUA(opts.customUA)
		if !opts.silent {
			fmt.Printf("  user-agent : custom (%d chars)\n", len(opts.customUA))
		}
	} else if opts.stealth || opts.randomAgent || rt.Ghost {
		client = client.WithRandomAgent(true)
		if opts.stealth || rt.Ghost {
			if !rt.Ghost {
				client = client.WithStealth(true)
			}
		}
		if !opts.silent {
			mode := "random-agent"
			if opts.stealth {
				mode = "stealth (random UA + jitter)"
			}
			if rt.Ghost {
				mode = "ghost (Chrome131 JA3, Pareto jitter, header-order, 40 UA pool)"
			}
			fmt.Printf("  anonymity  : %s\n", mode)
		}
	}
	if rt.ProxyPool != "" {
		var err error
		client, err = client.WithProxyPool(rt.ProxyPool)
		if err != nil {
			return nil, api.Config{}, err
		}
		if !opts.silent {
			fmt.Printf("  proxy-pool : %s\n", rt.ProxyPool)
		}
	} else if opts.proxyURL != "" {
		var err error
		client, err = client.WithProxy(opts.proxyURL)
		if err != nil {
			return nil, api.Config{}, err
		}
		if !opts.silent {
			fmt.Printf("  proxy      : %s\n", opts.proxyURL)
		}
	}
	if opts.rateLimit > 0 || opts.requestDelay > 0 {
		limiter := anpuhttp.NewRateLimiter(opts.rateLimit, opts.requestDelay)
		client = client.WithRateLimiter(limiter)
	} else if rt.Ghost {
		// Ghost without explicit rate-limit still adapts: Pareto jitter 800-3500ms
		// plus header/JA3 rotation; the RateLimiter fixed bucket remains when ghost off.
		limiter := anpuhttp.NewRateLimiter(2, 0) // adaptive 2 rps default for ghost ultra
		client = client.WithRateLimiter(limiter)
		if !opts.silent {
			fmt.Printf("  rate       : ghost adaptive 2 rps + Pareto jitter\n")
		}
	}
	// Stealth without explicit rate limit relies on per-request maybeJitter; no limiter needed.
	apiCfg := api.Config{
		OpenAPISource: opts.openAPI,
		GraphQLURL:    opts.graphQLURL,
		BaseURL:       opts.apiBaseURL,
	}
	return client, apiCfg, nil
}
