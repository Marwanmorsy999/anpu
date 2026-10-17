package integrations

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestToolVersionStderr(t *testing.T) {
	dir := t.TempDir()
	var path string
	var content string
	if runtime.GOOS == "windows" {
		path = filepath.Join(dir, "nuclei.bat")
		content = "@echo off\r\n" +
			"echo \x1b[32m3.7.0\x1b[0m 1>&2\r\n"
	} else {
		path = filepath.Join(dir, "nuclei")
		content = "#!/bin/sh\n" +
			"printf '\\033[32m3.7.0\\033[0m\\n' 1>&2\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := ToolVersion(context.Background(), path)
	if got != "3.7.0" {
		t.Fatalf("ToolVersion = %q, want %q", got, "3.7.0")
	}
}
