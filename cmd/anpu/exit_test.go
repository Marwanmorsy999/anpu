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
			args: []string{"scan", "http://example.com", "--output", "/invalid/path/that/does/not/exist/999"},
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
			// This will fail (exit 0) until Bug 8 is fixed, validating our fix.
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
