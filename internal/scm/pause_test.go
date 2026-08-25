package scm

import (
	"testing"
	"time"
)

// pauseFrom holds the rules that make a bounded pause worth anything, so it is
// tested directly rather than through a store - these have to hold on every
// platform, and only one of them has a registry to write to.

var pauseNow = time.Date(2026, 8, 20, 14, 0, 0, 0, time.UTC)

func TestNoRecordedPauseMeansProtectionIsOn(t *testing.T) {
	if got := pauseFrom("", pauseNow); got.Paused {
		t.Errorf("an empty pause value read as paused: %+v", got)
	}
}

func TestIndefinitePauseHasNoDeadline(t *testing.T) {
	got := pauseFrom(pauseIndefinite, pauseNow)
	if !got.Paused {
		t.Fatal("an indefinite pause did not read as paused")
	}
	if !got.Indefinite() {
		t.Errorf("an indefinite pause reported a deadline of %v", got.Until)
	}
}

func TestBoundedPauseReportsItsDeadline(t *testing.T) {
	until := pauseNow.Add(30 * time.Minute)
	got := pauseFrom(until.Format(time.RFC3339), pauseNow)
	if !got.Paused {
		t.Fatal("a pause with a future deadline did not read as paused")
	}
	if got.Indefinite() {
		t.Error("a pause with a deadline reported itself as indefinite")
	}
	if !got.Until.Equal(until) {
		t.Errorf("deadline is %v, want %v", got.Until, until)
	}
}

// The property the whole feature rests on: a pause ends by the clock, with
// nobody and nothing having to act on it. Even if the service never runs again,
// every reader agrees protection is back on once the deadline has passed - so the
// service noticing is how enforcement catches up, not how the pause ends.
func TestAPauseEndsOnItsOwnWhenTheDeadlinePasses(t *testing.T) {
	until := pauseNow.Add(30 * time.Minute)
	raw := until.Format(time.RFC3339)

	if got := pauseFrom(raw, until.Add(-time.Second)); !got.Paused {
		t.Error("a second before the deadline, protection was already back on")
	}
	if got := pauseFrom(raw, until); got.Paused {
		t.Error("at the deadline, the pause was still in force")
	}
	if got := pauseFrom(raw, until.Add(time.Hour)); got.Paused {
		t.Error("an hour past the deadline, the pause was still in force")
	}
	// A week later, with nothing having run in between.
	if got := pauseFrom(raw, until.Add(7*24*time.Hour)); got.Paused {
		t.Error("a week past the deadline, the pause was still in force")
	}
}

// An unreadable value means protection is on. This is deliberately the opposite
// of an unreadable lock deadline, which counts as locked - both fail towards
// protection being on, which is the direction that matters.
func TestAnUnreadablePauseValueMeansProtectionIsOn(t *testing.T) {
	for _, raw := range []string{"soon", "yes", "2026-08-20", "0", "  "} {
		if got := pauseFrom(raw, pauseNow); got.Paused {
			t.Errorf("%q read as paused; an unreadable value must fail towards protection", raw)
		}
	}
}

// A pause is not the teardown sentinel. They were the same thing once, and that
// is what made a pause unbounded - so this pins that reading one never answers
// for the other.
func TestPauseStateIsIndependentOfTheTeardownSentinel(t *testing.T) {
	if got := pauseFrom(pauseIndefinite, pauseNow); !got.Paused {
		t.Fatal("expected a paused state")
	}
	// PauseState carries no notion of the service being torn down, and nothing
	// here consults IsDisabled. The watchdog keeps IsDisabled for that, which is
	// exactly why it keeps resurrecting the service through a pause.
	if got := pauseFrom("", pauseNow); got.Paused || !got.Until.IsZero() {
		t.Errorf("a cleared pause is not the zero state: %+v", got)
	}
}
