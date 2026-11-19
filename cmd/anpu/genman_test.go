//go:build genman

package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/spf13/cobra/doc"
)

// TestGenMan regenerates man/anpu.1 from the cobra command tree.
// Run with: go test -tags genman -run TestGenMan ./cmd/anpu/
func TestGenMan(t *testing.T) {
	root := newRootCmd()
	header := &doc.GenManHeader{Title: "ANPU", Section: "1"}
	if err := os.MkdirAll("../../man", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := doc.GenManTree(root, header, "../../man"); err != nil {
		t.Fatal(err)
	}
	fmt.Println("generated man/anpu.1")
}
