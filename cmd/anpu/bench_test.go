package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSplitProfiles(t *testing.T) {
	got, err := splitProfiles("safe,advanced")
	if err != nil || len(got) != 2 || got[0] != "safe" || got[1] != "advanced" {
		t.Fatalf("got %v, %v", got, err)
	}
	got, err = splitProfiles(" Safe ,, ADVANCED ")
	if err != nil || len(got) != 2 || got[0] != "safe" || got[1] != "advanced" {
		t.Fatalf("whitespace/case must normalize: %v, %v", got, err)
	}
	for _, bad := range []string{"", "  ", "bogus", "safe,bogus"} {
		if _, err := splitProfiles(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestIsLoopbackTarget(t *testing.T) {
	yes := []string{
		"http://127.0.0.1:8901",
		"http://127.0.0.5/",
		"http://localhost:8901/",
		"http://[::1]:8901/",
	}
	for _, u := range yes {
		if !isLoopbackTarget(u) {
			t.Fatalf("%s must be loopback", u)
		}
	}
	no := []string{
		"http://192.168.1.1/",
		"http://10.0.0.1/",
		"http://example.com/",
		"http://[::2]/",
		"::not a url::",
		"",
	}
	for _, u := range no {
		if isLoopbackTarget(u) {
			t.Fatalf("%s must not be loopback", u)
		}
	}
}

func TestPickNewestJSON(t *testing.T) {
	dir := t.TempDir()
	if _, err := pickNewestJSON(dir); err == nil {
		t.Fatal("empty dir must error")
	}
	old := filepath.Join(dir, "a.json")
	newer := filepath.Join(dir, "b.json")
	if err := os.WriteFile(old, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Ensure distinct mtimes even on coarse filesystems.
	if err := os.Chtimes(old, time.Unix(0, 0), time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := pickNewestJSON(dir)
	if err != nil || got != newer {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestBenchCmdRegistered(t *testing.T) {
	root := newRootCmd()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "bench" {
			found = true
			if c.GroupID != "results" {
				t.Fatalf("bench must be in results group, got %q", c.GroupID)
			}
		}
	}
	if !found {
		t.Fatal("bench command not registered")
	}
}
