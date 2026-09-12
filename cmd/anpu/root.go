package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/anpu-project/anpu/internal/integrations"
	"github.com/anpu-project/anpu/internal/reporting"
	"github.com/anpu-project/anpu/pkg/version"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	flagConfigPath string
	flagVerbose    bool
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "anpu",
		Short:   "ANPU — Guard what you build. Open-source web security intelligence.",
		Version: version.Version,
		Long: `ANPU is an authorized web security analysis and attack-surface
intelligence tool. It orchestrates existing security tools (Nuclei,
OWASP ZAP) alongside its own passive analyzers, and
combines the results into a single, understandable security report.

ANPU must only be used against targets you own or are explicitly
authorized to test.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// No arguments: talk to the human. Interactive terminal →
			// numbered menu; pipes and scripts → classic help screen.
			if stdinInteractive() {
				return runWelcomeMenu(cmd)
			}
			printColorHelp(cmd, args)
			return nil
		},
	}

	root.SetHelpFunc(printColorHelp)

	root.PersistentFlags().StringVar(&flagConfigPath, "config", "", "path to a YAML config file (default: anpu.yaml in the current directory, if present)")
	root.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "show per-stage finding and warning counts")

	root.AddCommand(newScanCmd())
	root.AddCommand(newSafeCmd())
	root.AddCommand(newAdvancedCmd())
	root.AddCommand(newUltraCmd())
	root.AddCommand(newSearchCmd())
	root.AddCommand(newHistoryCmd())
	root.AddCommand(newShowCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newWatchCmd())
	root.AddCommand(newToolsCmd())
	root.AddCommand(newQueryCmd())
	root.AddCommand(newImportCmd())
	root.AddCommand(newFeedsCmd())
	root.AddCommand(newWordlistsCmd())
	root.AddCommand(newDriftCmd())

	// Group commands by what they do for you, so the list reads
	// clearly for first-time and non-technical users.
	// (Init the default completion/help commands first so they
	// can join a group instead of "Additional Commands:".)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	root.AddGroup(
		&cobra.Group{ID: "check", Title: "Check a website:"},
		&cobra.Group{ID: "results", Title: "See your results:"},
		&cobra.Group{ID: "setup", Title: "Set things up:"},
	)
	groupOf := map[string]string{
		"safe": "check", "advanced": "check", "ultra": "check",
		"scan": "check", "watch": "check",
		"show": "results", "history": "results", "diff": "results",
		"verify": "results",
		"query":  "results", "import": "results", "drift": "results",
		"tools": "setup", "search": "setup", "feeds": "setup",
		"wordlists": "setup", "completion": "setup", "help": "setup",
	}
	for _, c := range root.Commands() {
		if g, ok := groupOf[c.Name()]; ok {
			c.GroupID = g
		}
		// Plain-language one-liners for cobra's built-in commands.
		switch c.Name() {
		case "completion":
			c.Short = "Turn on tab-completion for your terminal"
		case "help":
			c.Short = "Show help for any command"
		}
	}

	return root
}

// printColorHelp renders banner + colorized help + first-run hint.
// Set as the root help func, subcommands inherit it, so every
// --help screen is branded the same way. The hint box prints only
// for the root screen.
func printColorHelp(cmd *cobra.Command, args []string) {
	opts := reporting.BannerOptions{}
	reporting.PrintBannerHeader(opts)
	fmt.Println()
	fmt.Print(reporting.ColorizeHelp(captureHelp(cmd), opts))
	if cmd == cmd.Root() {
		reporting.PrintFirstRunHint(opts)
	}
}

// captureHelp renders the default cobra help for cmd into a string.
func captureHelp(cmd *cobra.Command) string {
	root := cmd.Root()
	var buf bytes.Buffer
	prevOut := cmd.OutOrStdout()
	prevErr := cmd.ErrOrStderr()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetHelpFunc(nil)
	root.SetHelpFunc(nil)
	defer func() {
		cmd.SetOut(prevOut)
		cmd.SetErr(prevErr)
		cmd.SetHelpFunc(nil)
		root.SetHelpFunc(printColorHelp)
	}()
	_ = cmd.Help()
	return buf.String()
}

// stdinInteractive reports whether we can prompt the user.
// ANPU_FORCE_MENU=1 overrides for demos and tests.
func stdinInteractive() bool {
	if os.Getenv("ANPU_FORCE_MENU") == "1" {
		return true
	}
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// runWelcomeMenu is the bare-`anpu` experience: banner, numbered
// options, wait for input, then run the chosen command.
func runWelcomeMenu(cmd *cobra.Command) error {
	opts := reporting.BannerOptions{}
	reporting.PrintBannerHeader(opts)
	reporting.PrintWelcomeMenu(opts)

	in := bufio.NewReader(os.Stdin)
	const maxTries = 3
	for tries := 0; tries < maxTries; tries++ {
		if tries > 0 {
			reporting.PrintMenuPrompt(opts)
		}
		line, err := in.ReadString('\n')
		if err != nil {
			fmt.Println()
			return nil
		}
		choice := strings.TrimSpace(line)
		switch choice {
		case "1":
			return menuScan(cmd, in, "safe")
		case "2":
			return menuScan(cmd, in, "advanced")
		case "3":
			return menuScan(cmd, in, "ultra")
		case "4":
			return dispatch(cmd, "history")
		case "5":
			fmt.Println()
			fmt.Print(reporting.ColorizeHelp(captureHelp(cmd), opts))
			reporting.PrintFirstRunHint(opts)
			return nil
		case "6":
			return dispatch(cmd, "tools")
		case "0", "exit", "quit", "q":
			fmt.Println("See you — guard what you build.")
			return nil
		default:
			if choice == "" {
				fmt.Printf("Please pick a number (attempt %d/%d).\n", tries+1, maxTries)
			} else {
				fmt.Printf("Invalid choice %q (attempt %d/%d) — pick 1-6 or 0 to exit.\n", choice, tries+1, maxTries)
			}
		}
	}
	fmt.Println("No worries — run `anpu --help` any time to see every command.")
	return nil
}

// menuScan is the no-commands wizard: website, then run mode
// (standard/ghost-masked/adversarial), then numbered tool groups with a
// Select-All option, then install choice, outputs, network, and scope —
// then runs the chosen scan-level command exactly as if it had been typed.
func menuScan(cmd *cobra.Command, in *bufio.Reader, name string) error {
	target := ""
	for tries := 0; tries < 2; tries++ {
		fmt.Print("Website to check (e.g. https://example.com): ")
		line, err := in.ReadString('\n')
		if err != nil {
			fmt.Println()
			return nil
		}
		if t := strings.TrimSpace(line); t != "" {
			target = t
			break
		}
		fmt.Println("Please type a website address, or press Ctrl+C to leave.")
	}
	if target == "" {
		fmt.Println("No website entered — nothing to check. Bye for now.")
		return nil
	}
	modeArgs, modeLabel := askScanMode(in)
	toolArgs, toolLabel := askToolGroups(in)
	installArgs := askInstallMode(in, name, toolArgs)
	outputArgs, outputLabel := askOutputs(in)
	netArgs, netLabel := askNetworkExtras(in)
	scopeArgs, scopeLabel := askScopeFile(in)
	fmt.Println()
	fmt.Printf("Ready: %s | %s | %s | %s | %s | %s\n", name, modeLabel, toolLabel, installLabel(installArgs), outputLabel, netLabel)
	if scopeLabel != "" {
		fmt.Printf("Scope: %s\n", scopeLabel)
	}
	fmt.Print("Start now? [Y/n]: ")
	if line, err := in.ReadString('\n'); err == nil {
		if s := strings.ToLower(strings.TrimSpace(line)); s == "n" || s == "no" {
			fmt.Println("Cancelled — nothing ran. Run `anpu` any time to start again.")
			return nil
		}
	}
	fmt.Println()
	args := append([]string{target}, modeArgs...)
	args = append(args, toolArgs...)
	args = append(args, installArgs...)
	args = append(args, outputArgs...)
	args = append(args, netArgs...)
	args = append(args, scopeArgs...)
	return dispatch(cmd, name, args...)
}

// askScanMode is step 2 of the wizard: Standard (exposed/visible),
// Ghost masked-stealth, or Adversarial (aggressive, authorized only).
func askScanMode(in *bufio.Reader) ([]string, string) {
	fmt.Println()
	fmt.Println("How should the check run?")
	fmt.Println("  1) Standard — visible, normal fingerprints (exposed)")
	fmt.Println("  2) Ghost masked — stealth, harder to detect")
	fmt.Println("  3) Adversarial — deeper aggressive tests (authorized targets only)")
	fmt.Print("Pick 1-3 [1]: ")
	line, err := in.ReadString('\n')
	if err != nil {
		return nil, "Standard"
	}
	switch strings.TrimSpace(line) {
	case "2":
		fmt.Print("Proxy pool file (optional, Enter to skip): ")
		poolLine, err := in.ReadString('\n')
		if err != nil {
			return []string{"--ghost"}, "Ghost masked"
		}
		if p := strings.TrimSpace(poolLine); p != "" {
			if _, err := os.Stat(p); err != nil {
				fmt.Printf("Pool file %q not found — continuing without it.\n", p)
				return []string{"--ghost"}, "Ghost masked"
			}
			return []string{"--ghost", "--proxy-pool", p}, "Ghost masked + pool"
		}
		return []string{"--ghost"}, "Ghost masked"
	case "3":
		fmt.Print("Confirm you own or are authorized to test this target. Type YES to continue: ")
		confLine, err := in.ReadString('\n')
		if err != nil {
			return nil, "Standard"
		}
		if strings.ToLower(strings.TrimSpace(confLine)) != "yes" {
			fmt.Println("Not confirmed — continuing with a Standard check.")
			return nil, "Standard"
		}
		return []string{"--adversarial", "--confirm-authorized"}, "Adversarial"
	default:
		return nil, "Standard"
	}
}

// wizardToolGroup is one numbered checkbox in the tool picker. Mods must
// be valid --only names (core toggles or wrapper tags); unknown names are
// ignored downstream with a warning, never fatal.
type wizardToolGroup struct {
	Title string
	Mods  []string
}

var wizardToolGroups = []wizardToolGroup{
	{"Recon & subdomains", []string{"recon", "dnsintel", "ipintel", "rdap", "leak", "bgp", "archiveurls", "certsan", "certhistory", "dnsaudit", "emailharv", "emailauth", "csprecon", "socialhijack", "commentminer", "brokenlink", "originip", "subdomains", "subfinder", "amass", "assetfinder", "findomain", "dnsgen", "alterx", "gotator", "dnsrecon", "gau", "waybackurls", "subpermute", "axfrplus", "nsecwalk", "dnsx", "tlsx", "cdncheck", "asnmap"}},
	{"Crawl, API & endpoints", []string{"endpoints", "katana", "hakrawler", "gospider", "cariddi", "subjs", "api", "apiversion", "apiconsole", "graphqlfp", "graphqlschema", "soap", "oauthanalyzer", "samlmetadata", "kiterunner", "unfurl", "uro", "qsreplace"}},
	{"Active vuln & fuzz", []string{"active", "dirs", "ffuf", "gobuster", "feroxbuster", "dirsearch", "wfuzz", "nuclei", "nikto", "sqlmap", "ghauri", "xsstrike", "kxss", "gxss", "crlfuzz", "commix", "tplmap", "sstimap", "sstiexpand", "nosqlexpand", "nosqlmap", "redirectpack", "lfipack", "cvepack", "dotdotpwn", "smuggler", "oralyzer", "openredirex", "nomore403", "verbtamper", "forbiddenbypass", "cachedeception", "cors", "corsplus", "corsy", "methods", "debugmethods", "whatweb", "wafw00f", "wafdetect", "dalfox", "wpscan", "cmseek", "droopescan", "joomscan"}},
	{"Secrets, params & JS", []string{"secrets", "jssecrets", "jsluice", "secretfinder", "linkfinder", "gitleaks", "trufflehog", "noseyparker", "params", "arjun", "paramspider", "x8", "hiddenparams", "gfclassify"}},
	{"Network, takeover & bypass", []string{"portscan", "naabu", "nmap", "masscan", "rustscan", "takeover", "takeoverplus", "subzy", "subjack", "vhost", "cswsh", "h2fp", "h2smuggle", "shuffledns", "puredns", "metabigor", "webanalyze", "cspreconext", "hakoriginfinder"}},
	{"Headers, TLS, code & misc", []string{"technology", "httpx", "tls", "headers", "cookies", "clickjack", "policyheaders", "cookieprefix", "jwtplus", "jwtconfirm", "jwt_tool", "csrf", "sri", "backup", "backupplus", "deps", "osv-scanner", "grype", "trivy", "semgrep", "codesecrets", "searchsploit", "exposedgit", "exposedconfig", "git-dumper", "gitjacker", "actuator", "debugpages", "postmessage", "ppollute", "swscope", "timeoracle", "difforacle", "encodepoly", "oauthpack", "favicon", "faviconplus", "doh", "bucket", "authz", "idor", "zap", "gowitness", "aquatone", "socialhunter", "mobsf", "graphqlmap", "ssrfmap"}},
}

// askToolGroups is step 3 of the wizard: numbered multi-select with a
// Select-All option. No typing of tool names is required. Returns --only
// args (nil = all tools) plus a short label for the confirm line.
func askToolGroups(in *bufio.Reader) ([]string, string) {
	fmt.Println()
	fmt.Println("Which tools? (pick numbers, comma-separated)")
	for i, g := range wizardToolGroups {
		fmt.Printf("  %d) %s\n", i+1, g.Title)
	}
	fmt.Println("  A) All tools (recommended)")
	fmt.Print("Pick e.g. 1,3 or A [A]: ")
	line, err := in.ReadString('\n')
	if err != nil {
		return nil, "All tools"
	}
	s := strings.TrimSpace(line)
	if s == "" || strings.EqualFold(s, "a") || strings.EqualFold(s, "all") {
		return nil, "All tools"
	}
	picked := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.EqualFold(part, "a") || strings.EqualFold(part, "all") {
			return nil, "All tools"
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil || n < 1 || n > len(wizardToolGroups) {
			fmt.Printf("Ignoring %q — pick 1-%d or A.\n", part, len(wizardToolGroups))
			continue
		}
		picked[n-1] = true
	}
	if len(picked) == 0 || len(picked) == len(wizardToolGroups) {
		return nil, "All tools"
	}
	seen := map[string]bool{}
	var mods []string
	var titles []string
	for i, g := range wizardToolGroups {
		if !picked[i] {
			continue
		}
		titles = append(titles, g.Title)
		for _, m := range g.Mods {
			m = strings.ToLower(strings.TrimSpace(m))
			if m == "" || seen[m] {
				continue
			}
			seen[m] = true
			mods = append(mods, m)
		}
	}
	if len(mods) == 0 {
		fmt.Println("Nothing picked — running all tools.")
		return nil, "All tools"
	}
	return []string{"--only", strings.Join(mods, ",")}, "Groups: " + strings.Join(titles, " + ")
}

// askInstallMode is step 4 of the wizard: embedded-only, auto-install
// mid-scan, or install now. External binaries are never bundled; absent
// tools warn-and-skip unless installed.
func askInstallMode(in *bufio.Reader, level string, toolArgs []string) []string {
	fmt.Println()
	fmt.Println("Extra tools (amass, ffuf, nuclei, ...) are not bundled — they install on demand.")
	fmt.Println("  1) Embedded only — fastest, no downloads [default]")
	fmt.Println("  2) Auto-install during scan — full depth, downloads as needed")
	fmt.Println("  3) Install now, then scan — downloads first (slowest)")
	fmt.Print("Pick 1-3 [1]: ")
	line, err := in.ReadString('\n')
	if err != nil {
		return nil
	}
	switch strings.TrimSpace(line) {
	case "2":
		fmt.Println("Auto-install on: missing tools self-provision mid-scan.")
		return []string{"--auto-install", "--yes"}
	case "3":
		if installMissingForLevel(level, toolArgs) {
			fmt.Println("Install step done — running with newly installed tools.")
		} else {
			fmt.Println("Continuing with embedded coverage.")
		}
		return nil
	default:
		return nil
	}
}

// installMissingForLevel installs missing binaries for the level (and the
// picked --only subset when present). It continues past failures and
// returns true when at least one install succeeded or everything was
// already present.
func installMissingForLevel(level string, toolArgs []string) bool {
	only := map[string]bool{}
	if len(toolArgs) == 2 && toolArgs[0] == "--only" {
		for _, p := range strings.Split(toolArgs[1], ",") {
			if m := strings.ToLower(strings.TrimSpace(p)); m != "" {
				only[m] = true
			}
		}
	}
	var targets []string
	for _, s := range integrations.InstallableSpecs(runtime.GOOS) {
		r, ok := integrations.Get(s.Name)
		if !ok {
			continue
		}
		if level != "" && !strings.EqualFold(level, "ultra") && !strings.EqualFold(r.Level, level) {
			// ultra runs everything; safe/advanced stay level-scoped.
			continue
		}
		if len(only) > 0 {
			matched := false
			for m := range only {
				if strings.EqualFold(m, s.Name) || strings.EqualFold(m, s.ToggleName()) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if _, ok := integrations.LookupBinary(r.Binary); ok {
			continue
		}
		targets = append(targets, s.Name)
	}
	if len(targets) == 0 {
		fmt.Println("Everything needed is already installed (or covered embedded).")
		return true
	}
	fmt.Printf("Installing %d tool(s): %s\n", len(targets), strings.Join(targets, ", "))
	installed, failed := 0, 0
	ctx := context.Background()
	for _, name := range targets {
		r, ok := integrations.Get(name)
		if !ok {
			continue
		}
		fmt.Printf("Installing %s ...\n", name)
		if _, err := integrations.Install(ctx, r, 0); err != nil {
			fmt.Printf("  %s FAILED: %s\n", name, firstLine(err.Error()))
			failed++
			continue
		}
		fmt.Printf("  %s installed.\n", name)
		installed++
	}
	fmt.Printf("Install summary: %d installed/present, %d failed\n", installed, failed)
	return installed > 0 || failed == 0
}

func installLabel(args []string) string {
	for _, a := range args {
		if a == "--auto-install" {
			return "auto-install"
		}
	}
	return "embedded"
}

// askOutputs is step 5: report files without flags.
func askOutputs(in *bufio.Reader) ([]string, string) {
	fmt.Println()
	fmt.Println("Reports? (HTML always saved)")
	fmt.Println("  1) HTML only [default]")
	fmt.Println("  2) HTML + JSON (for automation)")
	fmt.Println("  3) HTML + JSON + SARIF (for CI tools)")
	fmt.Print("Pick 1-3 [1]: ")
	line, err := in.ReadString('\n')
	if err != nil {
		return nil, "HTML"
	}
	switch strings.TrimSpace(line) {
	case "2":
		return []string{"--json"}, "HTML+JSON"
	case "3":
		return []string{"--json", "--sarif"}, "HTML+JSON+SARIF"
	default:
		return nil, "HTML"
	}
}

// askNetworkExtras is step 6: quieter speed without flags.
func askNetworkExtras(in *bufio.Reader) ([]string, string) {
	fmt.Println()
	fmt.Println("Speed?")
	fmt.Println("  1) Normal [default]")
	fmt.Println("  2) Quieter — limit to ~2 requests/sec")
	fmt.Print("Pick 1-2 [1]: ")
	line, err := in.ReadString('\n')
	if err != nil {
		return nil, "normal speed"
	}
	if strings.TrimSpace(line) == "2" {
		return []string{"--rate-limit", "2"}, "quiet 2/sec"
	}
	return nil, "normal speed"
}

// askScopeFile is step 7: optional allowlist, Enter to skip.
func askScopeFile(in *bufio.Reader) ([]string, string) {
	fmt.Print("Scope allowlist file (optional, Enter to skip): ")
	line, err := in.ReadString('\n')
	if err != nil {
		return nil, ""
	}
	if p := strings.TrimSpace(line); p != "" {
		if _, err := os.Stat(p); err != nil {
			fmt.Printf("Scope file %q not found — continuing without it.\n", p)
			return nil, ""
		}
		return []string{"--scope-file", p}, p
	}
	return nil, ""
}

// dispatch runs a subcommand by name with args, exactly as if typed
// on the CLI (re-enters the root so flag parsing and hooks run).
func dispatch(cmd *cobra.Command, name string, args ...string) error {
	root := cmd.Root()
	root.SetArgs(append([]string{name}, args...))
	return root.ExecuteContext(cmd.Context())
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".anpu"
	}
	return filepath.Join(home, ".anpu")
}

func defaultDBPath() string {
	dir := defaultDataDir()
	_ = os.MkdirAll(dir, 0o750)
	return filepath.Join(dir, "anpu.db")
}

func resolveConfigPath() string {
	if flagConfigPath != "" {
		return flagConfigPath
	}
	if _, err := os.Stat("anpu.yaml"); err == nil {
		return "anpu.yaml"
	}
	return "anpu.yaml" // config.Load tolerates a missing file
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
