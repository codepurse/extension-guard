package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseUntil reads a deadline written either as a duration or as a moment.
//
// Both spellings are natural and somebody will reach for either: "2h" is what a
// person means when the answer is a length of time, and "2026-09-01T17:00" is
// what they mean when it is a point in it. Days are handled separately because Go
// durations stop at hours, and a day is the unit somebody actually types.
func parseUntil(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty deadline")
	}

	// "7d" - Go durations stop at hours, and days are the natural unit here.
	if days, ok := strings.CutSuffix(strings.ToLower(s), "d"); ok {
		if n, err := strconv.Atoi(days); err == nil {
			if n <= 0 {
				return time.Time{}, fmt.Errorf("deadline %q is not in the future", s)
			}
			return now.Add(time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return time.Time{}, fmt.Errorf("deadline %q is not in the future", s)
		}
		return now.Add(d), nil
	}

	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			if !t.After(now) {
				return time.Time{}, fmt.Errorf("deadline %q is not in the future", s)
			}
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot read deadline %q (try 72h, 7d, 2026-09-01, or 2026-09-01T17:00)", s)
}
