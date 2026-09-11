package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/anpu-project/anpu/internal/reporting"
	"github.com/anpu-project/anpu/pkg/models"
)

// reports.go — per-target artifact writing (Phase 6). Extracted verbatim
// from runScan's per-target loop: same filenames, same fallback
// semantics (first written report becomes the panel path).

// reportOutputs selects which artifacts a scan writes.
type reportOutputs struct {
	HTML  bool
	JSON  bool
	SARIF bool
	CSV   bool
	MD    bool
}

// writeOneReport writes a single artifact file. On failure it either
// returns the error (single-target scans abort) or warns, counts the
// failure, and reports skip=true so batch scans continue with the next
// target exactly as before.
func writeOneReport(kind, path string, fn func() error, target string, batch bool, scanErrors *int) (skip bool, err error) {
	if err := fn(); err != nil {
		if !batch {
			return false, err
		}
		_, _ = fmt.Fprintf(os.Stderr, "anpu: writing %s for %s: %v\n", kind, target, err)
		*scanErrors++
		return true, nil
	}
	return false, nil
}

// writeScanReports writes every selected artifact for one target and
// returns the panel report path (first artifact written). A non-nil
// error aborts; skip=true asks the target loop to continue with the
// next target (batch mode only).
func writeScanReports(summary *models.ScanSummary, opts reportOutputs, outputDir, slug, dateStr, target string, batch bool, scanErrors *int) (reportPath string, skip bool, err error) {
	write := func(kind, ext string, fn func(*models.ScanSummary, string) error) (bool, error) {
		p := filepath.Join(outputDir, fmt.Sprintf("%s-%s.%s", slug, dateStr, ext))
		skip, err := writeOneReport(kind, p, func() error { return fn(summary, p) }, target, batch, scanErrors)
		if err != nil || skip {
			return skip, err
		}
		if reportPath == "" {
			reportPath = p
		}
		return false, nil
	}
	if opts.HTML {
		if skip, err := write("HTML", "html", reporting.WriteHTML); err != nil || skip {
			return reportPath, skip, err
		}
	}
	if opts.JSON {
		if skip, err := write("JSON", "json", reporting.WriteJSON); err != nil || skip {
			return reportPath, skip, err
		}
	}
	if opts.SARIF {
		if skip, err := write("SARIF", "sarif", reporting.WriteSARIF); err != nil || skip {
			return reportPath, skip, err
		}
	}
	if opts.CSV {
		if skip, err := write("CSV", "csv", reporting.WriteCSV); err != nil || skip {
			return reportPath, skip, err
		}
	}
	if opts.MD {
		if skip, err := write("Markdown", "md", reporting.WriteMarkdown); err != nil || skip {
			return reportPath, skip, err
		}
	}
	return reportPath, false, nil
}
