package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
		"query": "results", "import": "results", "drift": "results",
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
		case "0", "exit", "quit", "q":
			fmt.Println("See you — guard what you build.")
			return nil
		default:
			if choice == "" {
				fmt.Printf("Please pick a number (attempt %d/%d).\n", tries+1, maxTries)
			} else {
				fmt.Printf("Invalid choice %q (attempt %d/%d) — pick 1-5 or 0 to exit.\n", choice, tries+1, maxTries)
			}
		}
	}
	fmt.Println("No worries — run `anpu --help` any time to see every command.")
	return nil
}

// menuScan asks for the website, then the run mode (standard/ghost/
// adversarial), then the tool scope (all vs picked subset) — then runs
// the chosen scan-level command exactly as if it had been typed.
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
	modeArgs := askScanMode(in)
	toolArgs := askToolScope(in)
	fmt.Println()
	args := append([]string{target}, append(modeArgs, toolArgs...)...)
	return dispatch(cmd, name, args...)
}

// askScanMode is step 2 of the wizard: Standard (exposed/visible),
// Ghost (stealth), or Adversarial (aggressive, authorized only).
func askScanMode(in *bufio.Reader) []string {
	fmt.Println()
	fmt.Println("How should the check run?")
	fmt.Println("  1) Standard — visible, normal fingerprints (exposed)")
	fmt.Println("  2) Ghost — stealth, harder to detect")
	fmt.Println("  3) Adversarial — deeper aggressive tests (authorized targets only)")
	fmt.Print("Pick 1-3 [1]: ")
	line, err := in.ReadString('\n')
	if err != nil {
		return nil
	}
	switch strings.TrimSpace(line) {
	case "2":
		fmt.Print("Proxy pool file (optional, Enter to skip): ")
		poolLine, err := in.ReadString('\n')
		if err != nil {
			return []string{"--ghost"}
		}
		if p := strings.TrimSpace(poolLine); p != "" {
			if _, err := os.Stat(p); err != nil {
				fmt.Printf("Pool file %q not found — continuing without it.\n", p)
				return []string{"--ghost"}
			}
			return []string{"--ghost", "--proxy-pool", p}
		}
		return []string{"--ghost"}
	case "3":
		fmt.Print("Confirm you own or are authorized to test this target. Type YES to continue: ")
		confLine, err := in.ReadString('\n')
		if err != nil {
			return nil
		}
		if strings.ToLower(strings.TrimSpace(confLine)) != "yes" {
			fmt.Println("Not confirmed — continuing with a Standard check.")
			return nil
		}
		return []string{"--adversarial", "--confirm-authorized"}
	default:
		return nil
	}
}

// askToolScope is step 3 of the wizard: all tools for the level, or a
// picked subset passed as --only (e.g. headers,tls).
func askToolScope(in *bufio.Reader) []string {
	fmt.Println()
	fmt.Println("Which tools?")
	fmt.Println("  1) All tools (recommended)")
	fmt.Println("  2) Pick specific tools")
	fmt.Print("Pick 1-2 [1]: ")
	line, err := in.ReadString('\n')
	if err != nil {
		return nil
	}
	if strings.TrimSpace(line) != "2" {
		return nil
	}
	fmt.Print("Type tool names, comma-separated (e.g. headers,tls — `anpu search <word>` lists names): ")
	listLine, err := in.ReadString('\n')
	if err != nil {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(listLine), ",")
	var mods []string
	for _, p := range parts {
		if m := strings.ToLower(strings.TrimSpace(p)); m != "" {
			mods = append(mods, m)
		}
	}
	if len(mods) == 0 {
		fmt.Println("No tools typed — running all tools.")
		return nil
	}
	return []string{"--only", strings.Join(mods, ",")}
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
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
