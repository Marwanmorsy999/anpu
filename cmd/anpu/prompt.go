package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// askConfirm prompts for a yes/no confirmation. assumeYes skips the
// prompt (CI / --yes). When interactive is false (piped stdin): strict
// mode refuses (safe for downloads — re-run with --yes), non-strict
// proceeds with a printed notice so scripts never hang. The typed
// default is always No.
func askConfirm(in io.Reader, out io.Writer, assumeYes, interactive, strict bool, question string) bool {
	if assumeYes {
		return true
	}
	if !interactive {
		if strict {
			_, _ = fmt.Fprintf(out, "%s [non-interactive without --yes: refusing]\n", question)
			return false
		}
		_, _ = fmt.Fprintf(out, "%s [non-interactive: proceeding]\n", question)
		return true
	}
	_, _ = fmt.Fprintf(out, "%s [y/N]: ", question)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		_, _ = fmt.Fprintln(out, "no confirmation read — aborting install step")
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}
