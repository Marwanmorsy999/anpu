package main

import (
	"context"
	"fmt"
	"os/exec"
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
				{"nuclei", "Nuclei", "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && nuclei -update-templates"},
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

func externalToolAvailable(binary string) bool {
	path, err := exec.LookPath(binary)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, path, "-version").Run() == nil
}
