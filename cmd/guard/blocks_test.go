package main

import (
	"testing"
	"time"
)

func TestParseUntil(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.Local)

	cases := []struct {
		in   string
		want time.Time
	}{
		{"72h", now.Add(72 * time.Hour)},
		{"30m", now.Add(30 * time.Minute)},
		{"7d", now.Add(7 * 24 * time.Hour)},
		{"1d", now.Add(24 * time.Hour)},
		{"2026-09-01", time.Date(2026, 9, 1, 0, 0, 0, 0, time.Local)},
		{"2026-09-01T17:00", time.Date(2026, 9, 1, 17, 0, 0, 0, time.Local)},
		{"2026-09-01 17:00", time.Date(2026, 9, 1, 17, 0, 0, 0, time.Local)},
		{" 72h ", now.Add(72 * time.Hour)},
	}
	for _, c := range cases {
		got, err := parseUntil(c.in, now)
		if err != nil {
			t.Errorf("parseUntil(%q): %v", c.in, err)
			continue
		}
		if !got.Equal(c.want) {
			t.Errorf("parseUntil(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseUntilRFC3339KeepsZone(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.Local)
	got, err := parseUntil("2026-09-01T17:00:00Z", now)
	if err != nil {
		t.Fatalf("parseUntil: %v", err)
	}
	if want := time.Date(2026, 9, 1, 17, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestParseUntilRejectsThePast matters because a deadline that has already
// passed is not a lock at all - accepting one would let "lock this for -5 days"
// read as success while leaving the block open.
func TestParseUntilRejectsThePast(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.Local)
	for _, in := range []string{"-5d", "0d", "-72h", "0h", "2020-01-01", "2026-08-17T11:00", "2026-08-17T12:00"} {
		if got, err := parseUntil(in, now); err == nil {
			t.Errorf("parseUntil(%q) = %v, want an error", in, got)
		}
	}
}

func TestParseUntilRejectsNonsense(t *testing.T) {
	now := time.Now()
	for _, in := range []string{"", "   ", "next tuesday", "soon", "d", "2026-13-45", "17:00"} {
		if got, err := parseUntil(in, now); err == nil {
			t.Errorf("parseUntil(%q) = %v, want an error", in, got)
		}
	}
}
