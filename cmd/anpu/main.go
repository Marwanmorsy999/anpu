// Command anpu is ANPU's CLI entry point.
package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Easier command: `anpu https://target.com --profile deep` rewrites
	// to `anpu scan https://target.com --profile deep` so the most common
	// invocation needs no subcommand. Anything that is already a known
	// subcommand or flag passes through untouched.
	rewriteScanShorthand()

	root := newRootCmd()
	if err := root.ExecuteContext(ctx); err != nil {
		fatal(err)
	}
}

// rewriteScanShorthand inserts "scan" after the binary name when the
// first argument looks like a scan target rather than a subcommand.
func rewriteScanShorthand() {
	if len(os.Args) < 2 {
		return
	}
	first := os.Args[1]
	if first == "" || first[0] == '-' {
		return
	}
	switch first {
	case "scan", "history", "show", "diff", "watch", "tools",
		"completion", "help", "version":
		return
	}
	if !looksLikeTarget(first) {
		return
	}
	os.Args = append([]string{os.Args[0], "scan"}, os.Args[1:]...)
}

// looksLikeTarget heuristically matches URLs and bare hostnames without
// hijacking typos of subcommand names (cobra still reports those when
// they don't look like targets).
func looksLikeTarget(s string) bool {
	if len(s) < 3 {
		return false
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return true
	}
	// Bare hostname or IP: must contain a dot or colon and no spaces.
	if strings.Contains(s, " ") {
		return false
	}
	return strings.Contains(s, ".") || strings.Contains(s, ":")
}
