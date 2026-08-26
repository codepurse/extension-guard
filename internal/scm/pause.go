package scm

import "time"

// A pause is protection switched off while the guard stays installed and
// running. It used to be the same thing as the teardown sentinel - Disable was
// literally Uninstall - and that is precisely what made a pause unbounded: it
// removed the service, so nothing was left running to notice a deadline, to
// resume, to keep re-asserting the trusted config, or to write the activity log
// during exactly the window protection was off. Splitting the two is what lets a
// pause end by itself.
//
// The two sentinels now mean different things and must not be confused:
//
//   - GuardDisabled (SetDisabled/IsDisabled) is a teardown. The service entry is
//     gone and the watchdog stands down. Only an uninstall sets it.
//   - The pause value below is a live state. The service keeps running, keeps
//     being resurrected by the watchdog, and enforces nothing.
//
// This file holds the interpretation; the raw string lives in the registry on
// Windows and the root-owned state file on Linux (pauseValue / setPauseValue).

// pauseIndefinite is the stored value for a pause with no deadline - one that
// ends only when somebody resumes it. Any other non-empty value is an RFC 3339
// deadline.
const pauseIndefinite = "indefinite"

// PauseState is what a recorded pause says at a given moment.
type PauseState struct {
	// Paused is whether protection is off right now.
	Paused bool
	// Until is when the pause lifts. Zero means it has no deadline, so it is only
	// meaningful when Paused is true.
	Until time.Time
}

// Indefinite reports whether the pause has no deadline.
func (p PauseState) Indefinite() bool { return p.Paused && p.Until.IsZero() }

// Pause records that protection is paused. A zero until means indefinitely -
// until somebody turns it back on.
func Pause(until time.Time) error {
	if until.IsZero() {
		return setPauseValue(pauseIndefinite)
	}
	return setPauseValue(until.Format(time.RFC3339))
}

// Resume clears any recorded pause.
func Resume() error { return setPauseValue("") }

// Paused reports whether protection is paused right now, and until when.
func Paused() PauseState { return pauseFrom(pauseValue(), time.Now()) }

// IsPaused is Paused().Paused, for the many callers that only need the boolean.
func IsPaused() bool { return Paused().Paused }

// pauseFrom interprets a stored pause value against a clock. It is separated
// from the store so the rules below can be tested on every platform, rather than
// only on one with a registry to write to.
//
// Two properties are worth being explicit about.
//
// A deadline that has passed reads as *not paused*, without anybody having to
// act on it. That is what makes a bounded pause trustworthy: the pause expires by
// the clock, so even if the service never ran again - killed, machine off for a
// week, an older build - every reader agrees protection is back on, and the next
// apply re-enforces. The service noticing and re-applying is how enforcement
// catches up, not how the pause ends.
//
// A value that cannot be read at all reads as not paused. This is the opposite of
// how an unreadable lock deadline is treated, and deliberately so: both fail
// towards protection being on. For a lock that means staying locked; for a pause
// it means the pause is over.
func pauseFrom(raw string, now time.Time) PauseState {
	switch raw {
	case "":
		return PauseState{}
	case pauseIndefinite:
		return PauseState{Paused: true}
	}
	until, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return PauseState{}
	}
	if !now.Before(until) {
		return PauseState{}
	}
	return PauseState{Paused: true, Until: until}
}
