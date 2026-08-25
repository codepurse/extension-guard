package main

import (
	"testing"
	"time"
)

// The activity list is scanned, not read line by line, so the one thing the
// timestamp has to get right is which day an entry belongs to.
func TestFriendlyTimeSaysWhichDay(t *testing.T) {
	// A zone with a positive offset, which is where the obvious implementation
	// goes wrong: rounding a timestamp against the UTC epoch puts the day boundary
	// at the offset rather than at local midnight.
	zone := time.FixedZone("+08", 8*60*60)
	now := time.Date(2026, 3, 10, 14, 30, 0, 0, zone) // a Tuesday

	cases := []struct {
		name string
		at   time.Time
		want string
	}{
		{"earlier today", time.Date(2026, 3, 10, 9, 4, 0, 0, zone), "09:04"},
		{"just after local midnight today", time.Date(2026, 3, 10, 0, 20, 0, 0, zone), "00:20"},
		{"before the zone offset today", time.Date(2026, 3, 10, 7, 59, 0, 0, zone), "07:59"},
		{"late yesterday", time.Date(2026, 3, 9, 23, 50, 0, 0, zone), "Yesterday 23:50"},
		{"early yesterday", time.Date(2026, 3, 9, 0, 5, 0, 0, zone), "Yesterday 00:05"},
		{"earlier this week", time.Date(2026, 3, 6, 21, 4, 0, 0, zone), "Fri 21:04"},
		{"a fortnight ago", time.Date(2026, 2, 24, 21, 4, 0, 0, zone), "24 Feb 21:04"},
	}
	for _, c := range cases {
		if got := friendlyTime(c.at, now); got != c.want {
			t.Errorf("%s: friendlyTime(%s) = %q, want %q", c.name, c.at.Format(time.RFC3339), got, c.want)
		}
	}
}

// A clock that has gone backwards (or an entry written a moment ahead of the
// read) must still read as today rather than as a date in the future.
func TestFriendlyTimeHandlesAnEntryFromTheFuture(t *testing.T) {
	now := time.Date(2026, 3, 10, 14, 30, 0, 0, time.UTC)
	ahead := now.Add(2 * time.Hour)
	if got := friendlyTime(ahead, now); got != "16:30" {
		t.Errorf("friendlyTime for an entry two hours ahead = %q, want the plain time", got)
	}
}

// Daylight saving makes one day 23 hours long, which naive division turns into
// zero days and mislabels "yesterday" as "today".
func TestFriendlyTimeSurvivesADaylightSavingShift(t *testing.T) {
	zone, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("zone data unavailable: %v", err)
	}
	// 8 March 2026 is the spring-forward day in the United States, so 7 March runs
	// 23 hours from midnight to midnight.
	now := time.Date(2026, 3, 8, 12, 0, 0, 0, zone)
	yesterday := time.Date(2026, 3, 7, 22, 15, 0, 0, zone)
	if got := friendlyTime(yesterday, now); got != "Yesterday 22:15" {
		t.Errorf("across the spring-forward boundary friendlyTime = %q, want %q", got, "Yesterday 22:15")
	}
}

// The cap exists so a frontend bug cannot turn one call into a walk over the
// whole log, and a nonsense limit has to land on the default rather than on zero.
func TestGetActivityClampsTheLimit(t *testing.T) {
	// GetActivity reads the real log, which on a machine with no install is simply
	// absent - so this asserts on the shape of the call, not on its contents.
	app := &App{}
	for _, limit := range []int{-5, 0, 1, maxActivityRows, maxActivityRows + 1000} {
		if got := app.GetActivity(limit); len(got) > maxActivityRows {
			t.Errorf("GetActivity(%d) returned %d rows, over the cap of %d", limit, len(got), maxActivityRows)
		}
	}
}
