package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anpu-project/anpu/internal/drift"
	"github.com/anpu-project/anpu/internal/storage"
	"github.com/anpu-project/anpu/pkg/models"
)

// newDriftCmd implements `anpu drift` (Wave 4 item 152): compare a
// current JSON report against an authorized baseline with parser-pin
// verification. Exit 1 on added findings or unreliable pins.
func newDriftCmd() *cobra.Command {
	var (
		pinsPath    string
		jsonOut     bool
		writePins   bool
		fromHistory string
	)
	cmd := &cobra.Command{
		Use:   "drift <baseline.json> <current.json>",
		Short: "Diff a scan against an authorized baseline with parser pins",
		Long: `Compare a current report against an authorized baseline.

Parser pins guard against silent detection changes: generate them with
` + "`anpu drift --write-pins --pins pins.json`" + ` and pass --pins on nightly runs.
A pin mismatch marks the comparison UNRELIABLE (exit 1) instead of
silently passing.

Examples:
  anpu drift --write-pins --pins pins.json
  anpu drift base.json now.json --pins pins.json --json
  anpu drift --from-history https://example.com/ --pins pins.json`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if writePins {
				if pinsPath == "" {
					return fmt.Errorf("--write-pins needs --pins <path>")
				}
				if err := drift.WritePins(pinsPath); err != nil {
					return err
				}
				fmt.Printf("Wrote parser pins to %s\n", pinsPath)
				return nil
			}
			var base, current *models.ScanSummary
			if fromHistory != "" {
				var err error
				base, current, err = historyPair(fromHistory)
				if err != nil {
					return err
				}
				fmt.Printf("Drift from history: %s (%s → %s)\n", fromHistory, base.ID, current.ID)
			} else {
				if len(args) != 2 {
					return fmt.Errorf("need baseline.json and current.json (or --write-pins or --from-history)")
				}
				var err error
				base, err = drift.LoadSummary(args[0])
				if err != nil {
					return err
				}
				current, err = drift.LoadSummary(args[1])
				if err != nil {
					return err
				}
			}
			pins, err := drift.LoadPins(pinsPath)
			if err != nil {
				return err
			}
			r := drift.Compare(base, current, pins)
			if jsonOut {
				raw, _ := json.MarshalIndent(r, "", "  ")
				fmt.Println(string(raw))
			} else {
				status := "RELIABLE"
				if !r.Reliable {
					status = "UNRELIABLE (parser drift)"
				}
				fmt.Printf("Drift %s: +%d/-%d findings, risk %.1f → %.1f, endpoints %+d\n",
					status, len(r.Added), len(r.Removed), r.RiskBefore, r.RiskAfter, r.EndpointDelta)
				for _, id := range r.Added {
					fmt.Printf("  + %s\n", id)
				}
				for _, id := range r.Removed {
					fmt.Printf("  - %s\n", id)
				}
				for _, p := range r.PinDrift {
					fmt.Printf("  ! pin: %s\n", p)
				}
			}
			if !r.Reliable || len(r.Added) > 0 {
				return fmt.Errorf("drift detected (unreliable pins or %d new findings)", len(r.Added))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&pinsPath, "pins", "", "parser-pin JSON from a previous --write-pins run")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print the comparison as JSON")
	cmd.Flags().BoolVar(&writePins, "write-pins", false, "write current parser pins to --pins path and exit")
	cmd.Flags().StringVar(&fromHistory, "from-history", "", "compare the two most recent stored scans for a target URL instead of files")
	return cmd
}

// historyPair loads the two most recent stored scans for a target
// (older first) for drift comparison.
func historyPair(target string) (base, current *models.ScanSummary, err error) {
	store, err := storage.Open(defaultDBPath())
	if err != nil {
		return nil, nil, fmt.Errorf("opening scan history database: %w", err)
	}
	defer store.Close()
	items, err := store.ListScans(50)
	if err != nil {
		return nil, nil, err
	}
	var ids []string
	for _, it := range items {
		if it.Target == target {
			ids = append(ids, it.ID)
			if len(ids) == 2 {
				break
			}
		}
	}
	if len(ids) < 2 {
		return nil, nil, fmt.Errorf("need two stored scans for %q to diff (found %d)", target, len(ids))
	}
	// ListScans returns most recent first: ids[0] is current.
	current, err = store.GetScan(ids[0])
	if err != nil {
		return nil, nil, err
	}
	base, err = store.GetScan(ids[1])
	if err != nil {
		return nil, nil, err
	}
	return base, current, nil
}
