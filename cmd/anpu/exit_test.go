package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestExitCodes(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "anpu.exe")

	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to build binary: %v", err)
	}

	// A path that is unwritable on every OS: its parent is an existing
	// file, so os.MkdirAll must fail (a plain "/invalid/..." path would
	// actually be creatable on Windows drives that allow root writes).
	blockerPath := filepath.Join(tmpDir, "blocker.txt")
	if err := os.WriteFile(blockerPath, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("failed to create blocker file: %v", err)
	}

	tests := []struct {
		name string
		args []string
		want int
	}{
		{
			name: "parse error",
			args: []string{"scan", "http://example.com", "--fail-on", "banana"},
			want: 1,
		},
		{
			name: "empty target arg",
			args: []string{"scan"},
			want: 1,
		},
		{
			name: "unwriteable output path",
			args: []string{"scan", "http://example.com", "--output", filepath.Join(blockerPath, "reports")},
			want: 1,
		},
		{
			name: "nonexistent scan id",
			args: []string{"show", "does-not-exist"},
			want: 1,
		},
		{
			name: "bare hostname",
			args: []string{"scan", "example.com"},
			want: 1,
		},
		{
			name: "unreachable target",
			args: []string{"scan", "http://nonexistent.invalid"},
			// The connectivity pre-check must fail the scan (exit 1),
			// not silently produce an empty "completed" report.
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binPath, tt.args...)
			cmd.Env = append(os.Environ(), "HOME="+tmpDir, "USERPROFILE="+tmpDir)
			err := cmd.Run()

			gotExit := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					gotExit = exitErr.ExitCode()
				} else {
					t.Fatalf("failed to run command: %v", err)
				}
			}

			if gotExit != tt.want {
				t.Errorf("got exit code %d, want %d", gotExit, tt.want)
			}
		})
	}
}
