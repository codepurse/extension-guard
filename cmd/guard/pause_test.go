package main

import (
	"testing"
	"time"
)

// pauseDeadline is what turns the -for flag into a moment to resume at, so it
// decides whether "30m" means half an hour or something the user did not ask for.

var pauseBase = time.Date(2026, 8, 20, 14, 0, 0, 0, time.UTC)

func TestNoDurationMeansAnIndefinitePause(t *testing.T) {
	for _, spec := range []string{"", "   "} {
		got, err := pauseDeadline(spec, pauseBase)
		if err != nil {
			t.Fatalf("%q: %v", spec, err)
		}
		if !got.IsZero() {
			t.Errorf("%q gave a deadline of %v, want an indefinite pause", spec, got)
		}
	}
}

func TestDurationsBecomeADeadline(t *testing.T) {
	cases := map[string]time.Duration{
		"30m":   30 * time.Minute,
		"2h":    2 * time.Hour,
		"1h30m": 90 * time.Minute,
		"1d":    24 * time.Hour,
		"7d":    7 * 24 * time.Hour,
	}
	for spec, want := range cases {
		got, err := pauseDeadline(spec, pauseBase)
		if err != nil {
			t.Errorf("%q: %v", spec, err)
			continue
		}
		if !got.Equal(pauseBase.Add(want)) {
			t.Errorf("%q gave %v, want %v", spec, got, pauseBase.Add(want))
		}
	}
}

// A duration that cannot be read has to be refused rather than quietly becoming
// an indefinite pause - that would turn a typo into protection being off until
// somebody happens to notice.
func TestAnUnreadableDurationIsRefused(t *testing.T) {
	for _, spec := range []string{"soon", "30 minutes", "-5m", "0", "tomorrow"} {
		if got, err := pauseDeadline(spec, pauseBase); err == nil {
			t.Errorf("%q was accepted and gave %v; an unreadable duration must be refused", spec, got)
		}
	}
}

// The console line and the activity entry come from the same helper, so what the
// user is told and what the record says cannot drift apart.
func TestPauseDetailReadsAsASentence(t *testing.T) {
	if got := pauseDetail(time.Time{}); got != "until it is turned back on" {
		t.Errorf("an indefinite pause is described as %q", got)
	}
	deadline := pauseBase.Add(time.Hour)
	got := pauseDetail(deadline)
	if want := "until " + deadline.Local().Format(time.RFC1123); got != want {
		t.Errorf("a bounded pause is described as %q, want %q", got, want)
	}
}
