package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newToolsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tools",
		Short: "Show which scan engines are available and how to enable missing ones",
		Long: `Report the status of ANPU's built-in engines and any optional
external integrations (nuclei). Built-in engines need no installation —
they are compiled into the anpu binary.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("ANPU engine status")
			fmt.Println()

			builtin := []struct {
				name string
				desc string
			}{
				{"Recon", "DNS, robots.txt, sitemap.xml, redirects, source maps"},
				{"Technology", "passive stack fingerprinting (headers, cookies, HTML/JS)"},
				{"TLS", "certificate validity/expiry, protocol versions, HTTPS redirect"},
				{"Headers", "security-header presence and quality"},
				{"Cookies", "Secure/HttpOnly/SameSite attribute audit"},
				{"Endpoints", "HTML/JS link, form, script, and API-path discovery"},
				{"Subdomains", "Certificate Transparency logs (+ DNS brute on deep)"},
				{"PortScan", "TCP connect scan of common service ports (deep)"},
				{"Dirs", "sensitive-path probing with soft-404 baseline"},
				{"Secrets", "API keys / tokens / private keys in discovered assets"},
				{"CORS", "origin-reflection and credentials misconfiguration"},
				{"Methods", "OPTIONS audit + live TRACE (XST) verification"},
			}
			for _, e := range builtin {
				fmt.Printf("  [built-in] ✓ %-12s %s\n", e.name, e.desc)
			}

			fmt.Println()
			ext := []struct {
				binary string
				label  string
				hint   string
			}{
				{"nuclei", "Nuclei", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates"},
				{"zap-cli", "OWASP ZAP", "https://www.zaproxy.org/download/ (integration ships in a future release)"},
			}
			for _, t := range ext {
				installed := externalToolAvailable(t.binary)
				sym, status := "✗", "not found"
				if installed {
					sym, status = "✓", "available"
				}
				fmt.Printf("  [optional] %s %-12s %s\n", sym, t.label, status)
				if !installed && t.binary == "nuclei" {
					fmt.Printf("               install: %s\n", t.hint)
				}
			}

			fmt.Println()
			fmt.Println("Profiles:")
			fmt.Println("  safe     passive analysis only")
			fmt.Println("  standard + dirs, secrets, CORS, methods, subdomain CT logs")
			fmt.Println("  deep     everything above + DNS brute-force + TCP port scan")
			return nil
		},
	}
}

// externalToolPath resolves a tool using PATH first, then common Go/bin
// locations. This keeps Windows installations working even when the
// Go bin directory is not on PATH.
func externalToolPath(binary string) (string, error) {
	if path, err := exec.LookPath(binary); err == nil {
		return path, nil
	}

	names := []string{binary}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(binary), ".exe") {
		names = append(names, binary+".exe")
	}

	candidates := make([]string, 0, 6)
	if gobin := strings.TrimSpace(os.Getenv("GOBIN")); gobin != "" {
		for _, name := range names {
			candidates = append(candidates, filepath.Join(gobin, name))
		}
	}
	if gopath := strings.TrimSpace(os.Getenv("GOPATH")); gopath != "" {
		first := strings.FieldsFunc(gopath, func(r rune) bool { return r == os.PathListSeparator })
		for _, gp := range first {
			for _, name := range names {
				candidates = append(candidates, filepath.Join(gp, "bin", name))
			}
		}
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%s not found on PATH or Go bin directories", binary)
}

func externalToolAvailable(binary string) bool {
	path, err := externalToolPath(binary)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, path, "-version").Run() == nil
}
