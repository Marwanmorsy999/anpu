package main

import (
	"bufio"
	"strings"
	"testing"
)

func readerFor(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}

func TestAskToolGroupsAll(t *testing.T) {
	for _, input := range []string{"\n", "A\n", "a\n", "all\n", "1,2,3,4,5,6\n", "bogus\n"} {
		args, label := askToolGroups(readerFor(input))
		if len(args) != 0 {
			t.Fatalf("input %q must mean all tools, got args %v", input, args)
		}
		if label != "All tools" {
			t.Fatalf("input %q label must be All tools, got %q", input, label)
		}
	}
}

func TestAskToolGroupsSubset(t *testing.T) {
	args, label := askToolGroups(readerFor("1,4\n"))
	if len(args) != 2 || args[0] != "--only" || args[1] == "" {
		t.Fatalf("subset must return --only list, got %v", args)
	}
	if !strings.Contains(args[1], "recon") || !strings.Contains(args[1], "secrets") {
		t.Fatalf("groups 1+4 must include recon and secrets mods, got %q", args[1])
	}
	if !strings.Contains(label, "Recon") {
		t.Fatalf("label must name groups, got %q", label)
	}
}

func TestAskOutputs(t *testing.T) {
	if args, _ := askOutputs(readerFor("\n")); len(args) != 0 {
		t.Fatalf("default must be HTML only, got %v", args)
	}
	if args, _ := askOutputs(readerFor("2\n")); len(args) != 1 || args[0] != "--json" {
		t.Fatalf("2 must be --json, got %v", args)
	}
	if args, _ := askOutputs(readerFor("3\n")); len(args) != 2 {
		t.Fatalf("3 must be --json --sarif, got %v", args)
	}
}

func TestAskScanModeDefaults(t *testing.T) {
	if args, label := askScanMode(readerFor("\n")); len(args) != 0 || label != "Standard" {
		t.Fatalf("default must be Standard, got %v %q", args, label)
	}
	if args, label := askScanMode(readerFor("2\n\n")); len(args) != 1 || args[0] != "--ghost" || label != "Ghost masked" {
		t.Fatalf("2 must be ghost masked, got %v %q", args, label)
	}
	if args, _ := askScanMode(readerFor("3\nno\n")); len(args) != 0 {
		t.Fatalf("declined adversarial must fall back to standard, got %v", args)
	}
	if args, label := askScanMode(readerFor("3\nYES\n")); len(args) != 2 || label != "Adversarial" {
		t.Fatalf("confirmed adversarial must pass flags, got %v %q", args, label)
	}
}

func TestInstallLabel(t *testing.T) {
	if installLabel(nil) != "embedded" {
		t.Fatal("nil must be embedded")
	}
	if installLabel([]string{"--auto-install", "--yes"}) != "auto-install" {
		t.Fatal("--auto-install must label auto-install")
	}
}
