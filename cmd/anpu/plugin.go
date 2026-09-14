package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	anpuhttp "github.com/Marwanmorsy999/anpu/internal/http"
	"github.com/Marwanmorsy999/anpu/pkg/models"
	"github.com/Marwanmorsy999/anpu/pkg/plugins"
	_ "github.com/Marwanmorsy999/anpu/pkg/plugins/example"
)

func newPluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Extend ANPU with YAML checks and Go plugins",
		Long: `Run user-supplied detections through ANPU's guarded fetching.

Plugins never touch the network directly: every request goes through
the same SSRF, local-network, timeout, and redirect guards as built-in
engines. See docs/plugins.md for the SDK contract and examples.`,
	}
	cmd.AddCommand(newPluginInitCmd())
	cmd.AddCommand(newPluginRunCmd())
	cmd.AddCommand(newPluginListCmd())
	return cmd
}

func newPluginInitCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold an example YAML check and Go plugin",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dir == "" {
				dir = "anpu-plugin-example"
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return err
			}
			yamlPath := filepath.Join(dir, "mycheck.yaml")
			goPath := filepath.Join(dir, "mycheck.go")
			if err := os.WriteFile(yamlPath, []byte(exampleCheckYAML), 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(goPath, []byte(examplePluginGo), 0o600); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "plugin: scaffolded %s and %s\n", yamlPath, goPath)
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "plugin: try it with `anpu plugin run --plugin %s <target>`\n", yamlPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "output directory (default anpu-plugin-example)")
	return cmd
}

func newPluginRunCmd() *cobra.Command {
	var pluginFile, pluginName, format string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a plugin file or registered plugin against a target",
		Long: `Execute exactly one plugin source against an authorized target:
either --plugin <file.yaml> (declarative checks) or --name <registered>
(a compiled-in Go plugin, see ` + "`anpu plugin list`" + `). Prints findings
as text, or JSON with --json for scripting. Exits 0 on a completed run
(even with findings); --fail-on is intentionally left to ` + "`anpu scan`" + `.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			if pluginFile == "" && pluginName == "" {
				return fmt.Errorf("one of --plugin <file.yaml> or --name <registered> is required")
			}
			if pluginFile != "" && pluginName != "" {
				return fmt.Errorf("--plugin and --name are mutually exclusive")
			}
			if format != "text" && format != "json" {
				return fmt.Errorf("invalid --format %q: want text or json", format)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()
			fetch := guardedPluginFetch(target)
			var findings []models.Finding
			var err error
			if pluginFile != "" {
				var checks []plugins.Check
				checks, err = plugins.LoadChecks(pluginFile)
				if err != nil {
					return err
				}
				findings, err = plugins.RunChecks(ctx, target, checks, fetch)
			} else {
				findings, err = plugins.RunNamed(ctx, pluginName, target, fetch)
			}
			if err != nil {
				return err
			}
			if format == "json" {
				data, err := json.MarshalIndent(findings, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(data))
				return nil
			}
			if len(findings) == 0 {
				fmt.Println("plugin: no findings")
				return nil
			}
			for _, f := range findings {
				fmt.Printf("[%s/%s] %s\n  %s\n", f.Severity, f.Confidence, f.Title, f.URL)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&pluginFile, "plugin", "", "YAML plugin file to execute")
	cmd.Flags().StringVar(&pluginName, "name", "", "registered Go plugin to execute")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func newPluginListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered Go plugins",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			names := plugins.List()
			if len(names) == 0 {
				fmt.Println("plugin: no Go plugins registered (YAML files run with `anpu plugin run --plugin`)")
				return nil
			}
			for _, n := range names {
				if p, ok := plugins.Lookup(n); ok {
					fmt.Printf("%-28s %s\n", n, p.Description())
				}
			}
			return nil
		},
	}
}

// guardedPluginFetch builds the host FetchFunc over ANPU's guarded HTTP
// client: SSRF, local-network, timeout, and redirect protections apply
// exactly as in scans. Loopback targets are allowed automatically (same
// rule as `anpu bench`); anything else inherits the caller's
// ANPU_ALLOW_LOCAL_NETWORK override, so private targets without it fail
// closed here too.
func guardedPluginFetch(target string) plugins.FetchFunc {
	allow := isLoopbackTarget(target) || os.Getenv("ANPU_ALLOW_LOCAL_NETWORK") == "1"
	client := anpuhttp.NewClientWithLocalNetworkAllowed(allow)
	return func(ctx context.Context, url string) (int, http.Header, []byte, error) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		resp, err := client.Get(cctx, url)
		if err != nil {
			return 0, nil, nil, err
		}
		return resp.StatusCode, resp.Header, resp.Body, nil
	}
}

const exampleCheckYAML = `checks:
  - name: generator-meta
    path: /
    match: '<meta\s+name="generator"'
    title: Generator meta tag discloses platform
    description: The homepage carries a generator meta tag, disclosing the exact platform to unauthenticated visitors.
    severity: low
    confidence: high
    category: technology-disclosure
    remediation: Remove the generator meta tag or strip version details.
`

const examplePluginGo = `// Example ANPU Go plugin: passive generator-meta disclosure check.
//
// Compile it into ANPU by importing this package (blank import
// registers it), then run with:
//
//	anpu plugin run --name example-generator-meta https://target.example
//
// Plugins never fetch directly: every request goes through the host
// FetchFunc with ANPU's safety guards. See docs/plugins.md.
package mycheck

import (
	"context"
	"strings"

	"github.com/Marwanmorsy999/anpu/pkg/models"
	"github.com/Marwanmorsy999/anpu/pkg/plugins"
)

func init() {
	plugins.Register(check{})
}

type check struct{}

func (check) Name() string { return "my-generator-meta" }

func (check) Description() string {
	return "Example plugin: generator meta tag disclosure."
}

func (check) Run(ctx context.Context, target string, fetch plugins.FetchFunc) ([]models.Finding, error) {
	status, _, body, err := fetch(ctx, strings.TrimSuffix(target, "/")+"/")
	if err != nil || status < 200 || status >= 300 {
		return nil, err
	}
	if !strings.Contains(strings.ToLower(string(body)), "<meta name=\"generator\"") {
		return nil, nil
	}
	return []models.Finding{{
		ID:              "plugin-my-generator-meta",
		Title:           "Generator meta tag discloses platform",
		Severity:        models.SeverityLow,
		Confidence:      models.ConfidenceHigh,
		Category:        models.CategoryTechnology,
		Target:          target,
		Source:          models.SourcePlugin,
		DetectionMethod: "example plugin: generator meta marker",
		Evidence:        models.Evidence{Observed: "generator meta tag present on homepage", Location: "homepage HTML"},
	}}, nil
}
`
