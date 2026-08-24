package integrations

import (
	"context"

	"github.com/anpu-project/anpu/internal/scanner"
)

// ZapScanner is a prepared integration point for OWASP ZAP. It is not
// implemented in this MVP — Available always returns false, so the
// pipeline skips it with a clear warning rather than pretending to run
// a scan that doesn't exist. This satisfies the scanner.Scanner
// interface today so the core pipeline and CLI (--no-zap, `zap: false`
// in config) already have a real integration point to wire up later,
// without requiring changes to the orchestrator.
//
// A real implementation would drive ZAP's REST API (or ZAP's Docker
// baseline/full scan scripts) the same way NucleiScanner drives the
// nuclei binary: detect availability, run only the scan policy
// appropriate for the selected profile, and convert ZAP's alert JSON
// into models.Finding via a converter analogous to convertNucleiFinding.
type ZapScanner struct{}

func NewZapScanner() *ZapScanner { return &ZapScanner{} }

func (z *ZapScanner) Name() string { return "zap" }

// Available always returns false in this MVP. See package doc.
func (z *ZapScanner) Available(ctx context.Context) bool { return false }

func (z *ZapScanner) Run(ctx context.Context, sc *scanner.ScanContext) (scanner.StageResult, error) {
	return scanner.StageResult{
		Warnings: []string{"ZAP integration is not yet implemented; this is a prepared interface for future work. Use --no-zap or zap: false to suppress this notice."},
	}, nil
}
