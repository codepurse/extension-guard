package main

import (
	"testing"

	"github.com/codepurse/extension-guard/internal/policy"
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

// The day list is what a person types or a chip row sends, so it takes both the
// spelled-out days and the groupings people say out loud.
func TestParseDayList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"daily", nil},
		{"weekdays", []string{"mon", "tue", "wed", "thu", "fri"}},
		{"weekends", []string{"sat", "sun"}},
		{"mon,wed,fri", []string{"mon", "wed", "fri"}},
		{" Mon, Wed ", []string{"mon", "wed"}},
		{"mon wed", []string{"mon", "wed"}},
	}
	for _, c := range cases {
		got, err := parseDayList(c.in)
		if err != nil {
			t.Errorf("parseDayList(%q): %v", c.in, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("parseDayList(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseDayList(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

// buildBlock is what turns the flags (and so the status window's form) into a
// block. The cases that matter are the two shapes - always-on and scheduled - and
// refusing half a window, which would otherwise become an always-on block by
// accident and silently enforce far more than the user asked for.
func TestBuildBlock(t *testing.T) {
	cfg := policy.Config{
		Extensions: []policy.Extension{{Name: "sieve"}},
		Blocks:     []policy.Block{{ID: "work-hours"}},
	}

	always, err := buildBlock(cfg, "", blockSpec{label: "Deep work"})
	if err != nil {
		t.Fatalf("buildBlock (always on): %v", err)
	}
	if always.ID != "deep-work" || len(always.Windows) != 0 || always.Narrows() {
		t.Errorf("always-on block = %+v", always)
	}

	// The derived id avoids the one already taken.
	dup, err := buildBlock(cfg, "", blockSpec{label: "Work hours"})
	if err != nil {
		t.Fatalf("buildBlock (duplicate label): %v", err)
	}
	if dup.ID != "work-hours-2" {
		t.Errorf("derived id = %q, want work-hours-2", dup.ID)
	}

	sched, err := buildBlock(cfg, "", blockSpec{
		label: "Work", days: "weekdays", from: "09:00", to: "17:00", extensions: "sieve",
	})
	if err != nil {
		t.Fatalf("buildBlock (scheduled): %v", err)
	}
	if !sched.Narrows() || len(sched.Windows) != 1 {
		t.Fatalf("scheduled block = %+v", sched)
	}
	if got := sched.Windows[0].Summary(); got != "Mon-Fri 09:00-17:00" {
		t.Errorf("window summary = %q", got)
	}
	if len(sched.Extensions) != 1 || sched.Extensions[0] != "sieve" {
		t.Errorf("governed extensions = %v", sched.Extensions)
	}

	if _, err := buildBlock(cfg, "", blockSpec{label: "Half", from: "09:00"}); err == nil {
		t.Error("expected half a window to be refused")
	}
	if _, err := buildBlock(cfg, "", blockSpec{label: "Half", to: "17:00"}); err == nil {
		t.Error("expected half a window to be refused")
	}
}
