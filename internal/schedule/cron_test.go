package schedule

import (
	"testing"
	"time"
)

func TestParse_Valid(t *testing.T) {
	cases := []string{
		"* * * * *",
		"0 * * * *",
		"0 0 * * *",
		"*/15 * * * *",
		"0 9-17 * * 1-5",
		"30 6 1,15 * *",
		"@hourly",
		"@daily",
		"@weekly",
		"@monthly",
	}
	for _, expr := range cases {
		if _, err := Parse(expr); err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", expr, err)
		}
	}
}

func TestParse_Invalid(t *testing.T) {
	cases := []string{
		"",
		"* * * *",     // only 4 fields
		"60 * * * *",  // minute out of range
		"* 25 * * *",  // hour out of range
		"* * 0 * *",   // dom out of range (min 1)
		"* * * 13 *",  // month out of range
		"* * * * 7",   // dow out of range (0-6)
		"*/0 * * * *", // step zero
		"abc * * * *", // non-numeric
	}
	for _, expr := range cases {
		if _, err := Parse(expr); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", expr)
		}
	}
}

func TestNext_EveryMinute(t *testing.T) {
	sched, _ := Parse("* * * * *")
	now := time.Date(2026, 1, 1, 12, 30, 45, 0, time.UTC)
	next := sched.Next(now)
	want := time.Date(2026, 1, 1, 12, 31, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %v, want %v", next, want)
	}
}

func TestNext_Hourly(t *testing.T) {
	sched, _ := Parse("@hourly")
	now := time.Date(2026, 1, 1, 12, 30, 0, 0, time.UTC)
	next := sched.Next(now)
	want := time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %v, want %v", next, want)
	}
}

func TestNext_Daily(t *testing.T) {
	sched, _ := Parse("@daily")
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	next := sched.Next(now)
	want := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %v, want %v", next, want)
	}
}

func TestNext_EveryFifteenMinutes(t *testing.T) {
	sched, _ := Parse("*/15 * * * *")
	now := time.Date(2026, 1, 1, 12, 14, 0, 0, time.UTC)
	next := sched.Next(now)
	want := time.Date(2026, 1, 1, 12, 15, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %v, want %v", next, want)
	}
}

func TestNext_WeekdaysOnly(t *testing.T) {
	sched, _ := Parse("0 9 * * 1-5") // 9am Mon-Fri
	// Jan 3 2026 is a Saturday
	now := time.Date(2026, 1, 3, 10, 0, 0, 0, time.UTC)
	next := sched.Next(now)
	// Next Monday Jan 5
	want := time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %v, want %v", next, want)
	}
}

func TestNext_AlwaysStrictlyAfterNow(t *testing.T) {
	sched, _ := Parse("* * * * *")
	now := time.Now()
	next := sched.Next(now)
	if !next.After(now) {
		t.Errorf("Next(%v) = %v is not strictly after now", now, next)
	}
}
