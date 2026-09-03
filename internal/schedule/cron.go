// Package schedule provides a minimal 5-field cron expression parser.
//
// Supported syntax per field (minute hour dom month dow):
//   - "*"        — every value
//   - "*/N"      — every N-th value
//   - "N"        — exact value
//   - "N,M,..."  — list of values
//   - "N-M"      — inclusive range
//
// Macros: @hourly, @daily, @midnight, @weekly, @monthly.
//
// Not supported: @reboot, L/W/# modifiers, seconds field.
package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// fieldSpec holds the resolved set of valid integers for one cron field.
type fieldSpec struct {
	values map[int]struct{}
	min    int
	max    int
}

// Schedule holds parsed cron fields ready for next-trigger calculation.
type Schedule struct {
	minute fieldSpec
	hour   fieldSpec
	dom    fieldSpec // day of month
	month  fieldSpec
	dow    fieldSpec // day of week (0=Sun)
	expr   string
}

// Expression returns the canonical cron expression string.
func (s *Schedule) Expression() string { return s.expr }

// Parse parses a 5-field cron expression and returns a Schedule.
func Parse(expr string) (*Schedule, error) {
	expr = strings.TrimSpace(expr)

	// Expand macros.
	switch expr {
	case "@hourly":
		expr = "0 * * * *"
	case "@daily", "@midnight":
		expr = "0 0 * * *"
	case "@weekly":
		expr = "0 0 * * 0"
	case "@monthly":
		expr = "0 0 1 * *"
	}

	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron expression must have 5 fields (got %d): %q", len(fields), expr)
	}

	limits := [5][2]int{
		{0, 59}, // minute
		{0, 23}, // hour
		{1, 31}, // dom
		{1, 12}, // month
		{0, 6},  // dow
	}

	specs := make([]fieldSpec, 5)
	for i, f := range fields {
		sp, err := parseField(f, limits[i][0], limits[i][1])
		if err != nil {
			return nil, fmt.Errorf("field %d (%q): %w", i+1, f, err)
		}
		specs[i] = sp
	}

	return &Schedule{
		minute: specs[0],
		hour:   specs[1],
		dom:    specs[2],
		month:  specs[3],
		dow:    specs[4],
		expr:   expr,
	}, nil
}

// Next returns the next trigger time strictly after t, in the same location.
func (s *Schedule) Next(t time.Time) time.Time {
	// Truncate to minute precision and advance by 1 minute to find next match.
	t = t.Truncate(time.Minute).Add(time.Minute)

	// Search up to 4 years (covers all cron combinations including Feb 29).
	limit := t.Add(4 * 365 * 24 * time.Hour)

	for t.Before(limit) {
		if _, ok := s.month.values[int(t.Month())]; !ok {
			// Advance to start of next month.
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
			continue
		}
		_, domOK := s.dom.values[t.Day()]
		_, dowOK := s.dow.values[int(t.Weekday())]
		if !domOK || !dowOK {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
			continue
		}
		if _, ok := s.hour.values[t.Hour()]; !ok {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
			continue
		}
		if _, ok := s.minute.values[t.Minute()]; !ok {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	// Should never be reached for a valid schedule.
	panic("schedule.Next: no match found within 4 years — cron expression may be invalid")
}

// parseField converts a single cron field string into a fieldSpec.
func parseField(s string, min, max int) (fieldSpec, error) {
	sp := fieldSpec{values: make(map[int]struct{}), min: min, max: max}

	parts := strings.Split(s, ",")
	for _, part := range parts {
		if err := parsePart(part, min, max, sp.values); err != nil {
			return fieldSpec{}, err
		}
	}
	return sp, nil
}

func parsePart(s string, min, max int, out map[int]struct{}) error {
	// Handle step: "*/N" or "N-M/N"
	step := 1
	if idx := strings.Index(s, "/"); idx >= 0 {
		var err error
		step, err = strconv.Atoi(s[idx+1:])
		if err != nil || step < 1 {
			return fmt.Errorf("invalid step %q", s[idx+1:])
		}
		s = s[:idx]
	}

	var lo, hi int

	if s == "*" {
		lo, hi = min, max
	} else if idx := strings.Index(s, "-"); idx >= 0 {
		var err error
		lo, err = strconv.Atoi(s[:idx])
		if err != nil {
			return fmt.Errorf("invalid range start %q", s[:idx])
		}
		hi, err = strconv.Atoi(s[idx+1:])
		if err != nil {
			return fmt.Errorf("invalid range end %q", s[idx+1:])
		}
	} else {
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("invalid value %q", s)
		}
		lo, hi = n, n
	}

	if lo < min || hi > max || lo > hi {
		return fmt.Errorf("value %d-%d out of range [%d, %d]", lo, hi, min, max)
	}
	for v := lo; v <= hi; v += step {
		out[v] = struct{}{}
	}
	return nil
}
