package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/codepurse/extension-guard/internal/usage"
)

// This file adds time limits: "forty-five minutes of this a day, and then it is
// blocked until tomorrow".
//
// A limit is the third way a block can decide it is not enforcing right now, and
// the three compose rather than competing. A block with no windows and no limit is
// on around the clock. Windows say *when* it may enforce. A limit says it enforces
// only once its budget for the day is gone. So the question "is this block
// enforcing?" reads: in one of its windows, and out of time.
//
// Why a limit hangs off a block rather than off an app. The block is already the
// unit that groups things and carries the lock, and a budget shared by a group is
// the thing people actually want - "an hour of games", not "an hour of each game,
// so three hours if I own three". One app per block gives the per-app version of
// the feature for free, and the reverse would not have been true.
//
// Why only applications. A limit needs usage measured, and the guard can only
// measure what it can watch: the process list, once a second, in the app sweep. A
// blocked site is enforced by handing the browser a policy and trusting it - there
// is no signal coming back, so "thirty minutes of Reddit" would be a promise
// nothing here could keep. Validate refuses it rather than accepting a limit that
// silently never fires, which is the same rule this package already applies to a
// window that can never open.
//
// What is measured is *running*, not *focused*. A game left open in the background
// spends its budget. That is the less flattering of the two readings, and it is the
// one chosen deliberately: window focus is not visible from a service (session 0
// cannot see the user's desktop - see appblock_windows.go), so the alternative
// would depend on the session helper being alive, and a limit that stops counting
// when nobody is signed in is a limit with an obvious way around it. Over-counting
// fails towards the commitment; under-counting fails away from it.

// DefaultResetAt is when the day rolls over if the config does not say. Midnight
// is the least surprising answer, but it is worth being able to change: somebody
// whose limit is "an hour of games in the evening" and who is still up at 00:30
// should not be handed a fresh hour mid-session, and a reset at 04:00 matches what
// a person means by "a day" better than the calendar does.
const DefaultResetAt = "00:00"

// MaxLimit is the longest daily budget accepted. A limit longer than the day it
// applies to can never be reached, so it would look like protection and be none -
// the same failure Validate already refuses for a zero-length window.
const MaxLimit = 24 * time.Hour

// dayFormat is how a day is keyed in the ledger. Dates in this layout sort as
// strings, which internal/usage relies on to tell one day from an earlier one.
const dayFormat = "2006-01-02"

// spentOn is how the current day's counters are read. A var so tests can supply
// them without a ledger on disk; the real one reads the file internal/usage owns.
var spentOn = usage.Spent

// Spent is how much of each limited block's daily budget has been used, as of some
// moment. It is passed into resolution rather than read inside it, so that the
// service can resolve against its own live counters - which are up to a flush
// interval ahead of what is on disk - while everything else reads the file.
//
// Unreadable is the fail-closed case: a ledger that exists and cannot be parsed
// means every limit reads as spent. The alternative is to treat a damaged counter
// as zero, which would turn "corrupt the file" into "reset my limits", and that is
// exactly the move the feature has to survive. It also self-heals: the service
// rewrites the ledger on its next flush, and the file it writes parses.
type Spent struct {
	ByBlock    map[string]time.Duration
	Unreadable bool
}

// On is how much of a block's budget has gone.
func (s Spent) On(id string) time.Duration { return s.ByBlock[usage.Key(id)] }

// ParseLimit reads a daily budget. It accepts what a person would type: "45m",
// "1h30m", "1.5h", or a bare number meaning minutes.
//
// Bare minutes exist because "45" is what someone writes in a form field labelled
// minutes, and rejecting it would be a lesson in Go's duration syntax rather than
// a helpful error.
func ParseLimit(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("no time limit given")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		mins, mErr := strconv.ParseFloat(s, 64)
		if mErr != nil {
			return 0, fmt.Errorf("cannot read time limit %q (try 45m, 1h30m, or a number of minutes)", s)
		}
		d = time.Duration(mins * float64(time.Minute))
	}
	if d <= 0 {
		return 0, fmt.Errorf("time limit %q is not a length of time", s)
	}
	if d > MaxLimit {
		return 0, fmt.Errorf("time limit %s is longer than a day, so it would never be reached", HumanDuration(d))
	}
	// Rounded down to whole seconds because that is the resolution the ledger
	// counts in; a limit of "45m30.5s" that can never be exactly met would be a
	// puzzle rather than a feature.
	return d.Truncate(time.Second), nil
}

// HasLimit reports whether this block carries a daily budget.
func (b Block) HasLimit() bool { return strings.TrimSpace(b.Limit) != "" }

// LimitFor returns the block's parsed daily budget, and whether it has a usable
// one. An unparseable limit reports false, which makes the block enforce around the
// clock rather than not at all - Validate refuses to load the config in the first
// place, and if one ever got past it, failing towards enforcement is the direction
// this package always takes.
func (b Block) LimitFor() (time.Duration, bool) {
	if !b.HasLimit() {
		return 0, false
	}
	d, err := ParseLimit(b.Limit)
	if err != nil {
		return 0, false
	}
	return d, true
}

// limitOrZero is the block's budget for comparison purposes: the parsed duration,
// or zero for a block with no limit or an unreadable one. Two blocks whose limits
// are both unreadable compare equal, which is right - neither can be enforced, and
// the config does not load either way.
func (b Block) limitOrZero() time.Duration {
	d, _ := b.LimitFor()
	return d
}

// Exhausted reports whether the block's budget for the day is gone. A block with
// no limit is never exhausted; it has no budget to run out of.
func (b Block) Exhausted(sp Spent) bool {
	limit, ok := b.LimitFor()
	if !ok {
		return false
	}
	if sp.Unreadable {
		return true // see Spent
	}
	return sp.On(b.ID) >= limit
}

// Remaining is how much of the budget is left, never negative. Only for display:
// enforcement asks Exhausted, which does not have to decide what a negative
// remainder would mean.
func (b Block) Remaining(sp Spent) time.Duration {
	limit, ok := b.LimitFor()
	if !ok {
		return 0
	}
	if sp.Unreadable {
		return 0
	}
	if left := limit - sp.On(b.ID); left > 0 {
		return left
	}
	return 0
}

// EnforcingAt is the whole question in one place: is this block enforcing at this
// moment? In one of its windows, and - if it has a limit - out of budget.
func (b Block) EnforcingAt(at time.Time, sp Spent) bool {
	if !b.InWindow(at) {
		return false
	}
	if !b.HasLimit() {
		return true
	}
	return b.Exhausted(sp)
}

// LimitSummary renders the budget for display: "45m/day", or "" for a block
// without one.
func (b Block) LimitSummary() string {
	limit, ok := b.LimitFor()
	if !ok {
		return ""
	}
	return HumanDuration(limit) + "/day"
}

// AnyLimits reports whether any block carries a limit. Everything that costs
// something - reading the ledger, snapshotting the process list to measure - is
// behind this check, so a config with no limits pays nothing for the feature.
func (c Config) AnyLimits() bool {
	for _, b := range c.Blocks {
		if b.HasLimit() {
			return true
		}
	}
	return false
}

// LimitedBlocks returns the blocks that carry a limit.
func (c Config) LimitedBlocks() []Block {
	var out []Block
	for _, b := range c.Blocks {
		if b.HasLimit() {
			out = append(out, b)
		}
	}
	return out
}

// resetMinutes is when the day starts, in minutes past midnight.
func (c Config) resetMinutes() int {
	if mins, ok := parseHM(strings.TrimSpace(c.ResetAt)); ok {
		return mins
	}
	return 0 // unset, or unparseable and reported by Validate
}

// DayKey names the day that a moment belongs to, which is what the ledger files
// counters under. With a reset at 04:00, everything from 04:00 on the 20th until
// 03:59 on the 21st is the 20th.
//
// The arithmetic is absolute rather than calendar-aware, so on the two days a year
// the clocks change, the boundary lands an hour early or late. Being an hour out
// once each way, on a counter that resets daily, is not worth the complexity of
// getting it exactly right.
func (c Config) DayKey(at time.Time) string {
	return at.Add(-time.Duration(c.resetMinutes()) * time.Minute).Format(dayFormat)
}

// SpentAt reads the day's counters from the ledger. This is the default path -
// what the CLI and the status window get - and it is why every resolution entry
// point has a plain form as well as a ...With one: a caller that does not know
// about limits still resolves them correctly, rather than silently treating every
// budget as untouched.
func (c Config) SpentAt(at time.Time) Spent {
	if !c.AnyLimits() {
		return Spent{}
	}
	byBlock, state := spentOn(c.DayKey(at))
	return Spent{ByBlock: byBlock, Unreadable: state == usage.StateUnreadable}
}

// MeasuredApps returns the app rules whose running time counts towards a block's
// limit: the ones it governs that the user has not switched off.
//
// It reads the enabled list of the *unresolved* config on purpose. In the resolved
// one, an app under a limit that still has budget left has been turned off - that
// is how "not blocked right now" is expressed - and measuring the resolved config
// would therefore stop counting the moment there was budget to count against.
func (c Config) MeasuredApps(b Block) []App {
	var out []App
	for _, a := range c.BlockedApps() {
		if b.GovernsApp(a) {
			out = append(out, a)
		}
	}
	return out
}

// RunningLimited returns the ids of limited blocks that are being used right now:
// in window, and with at least one of the apps they govern running.
//
// Out-of-window time is not charged. A block with a window and a limit reads as
// "forty-five minutes during these hours", so an hour spent in the app when the
// block is not enforcing anything is not spending a budget that only applies
// later. For the common case - a limit and no windows - InWindow is always true
// and the distinction never arises.
func (c Config) RunningLimited(at time.Time, procs []Process) []string {
	var out []string
	for _, b := range c.Blocks {
		if !b.HasLimit() || !b.InWindow(at) {
			continue
		}
		if anyRunning(c.MeasuredApps(b), procs) {
			out = append(out, usage.Key(b.ID))
		}
	}
	return out
}

// anyRunning reports whether any of these rules matches a running process. Note
// that it does not care how many: a block is being used or it is not, and two
// copies of the same game do not spend the budget twice as fast.
func anyRunning(apps []App, procs []Process) bool {
	for _, p := range procs {
		for _, a := range apps {
			if a.Matches(p) {
				return true
			}
		}
	}
	return false
}

// MeasurementNeeds reports whether there is anything to measure at this moment
// and, if so, what a sample of the process list has to collect.
//
// All three answers are needed before taking the sample rather than after, because
// the sample is the expensive part: an image path costs a handle per process and a
// window title costs a pass over every top-level window. A machine with no limits,
// or with all of them out of window, does not look at the process list at all.
func (c Config) MeasurementNeeds(at time.Time) (measure, paths, titles bool) {
	for _, b := range c.Blocks {
		if !b.HasLimit() || !b.InWindow(at) {
			continue
		}
		apps := c.MeasuredApps(b)
		if len(apps) == 0 {
			continue // nothing it covers is switched on, so there is nothing to count
		}
		measure = true
		paths = paths || NeedsPaths(apps)
		titles = titles || NeedsTitles(apps)
	}
	return measure, paths, titles
}

// validateLimits reports the first thing about a limit that would make it behave in
// a way its author did not intend. It is strict for the reason the rest of Validate
// is: a limit that quietly never fires leaves someone believing they are protected.
func (c Config) validateLimits() error {
	if s := strings.TrimSpace(c.ResetAt); s != "" {
		if _, ok := parseHM(s); !ok {
			return fmt.Errorf("resetAt %q is not a time of day (want HH:MM)", c.ResetAt)
		}
	}
	for _, b := range c.Blocks {
		if !b.HasLimit() {
			continue
		}
		if _, err := ParseLimit(b.Limit); err != nil {
			return fmt.Errorf("block %q: %w", b.ID, err)
		}
		// Everything below is the same objection stated three ways: a limit can only
		// be enforced on something whose use the guard can see, and it can only see
		// applications.
		if b.governsAll() {
			return fmt.Errorf("block %q has a time limit but does not say what it covers; "+
				"a limit has to name applications, because that is all the guard can measure", b.ID)
		}
		if len(b.Extensions) > 0 || len(b.Domains) > 0 {
			return fmt.Errorf("block %q has a time limit and covers extensions or sites; "+
				"a limit can only cover applications, because browser time is enforced by the browser "+
				"and never reported back", b.ID)
		}
		if len(b.Apps) == 0 {
			return fmt.Errorf("block %q has a time limit but covers no applications", b.ID)
		}
	}
	return nil
}

// HumanDuration renders a duration the way a person says it: "45m", "1h30m", "2h".
// Rounded to whole minutes, because that is the unit a budget is set in and a
// display that counts seconds invites watching it.
func HumanDuration(d time.Duration) string {
	if d <= 0 {
		return "0m"
	}
	if d < time.Minute {
		return "under a minute"
	}
	mins := int(d.Round(time.Minute) / time.Minute)
	h, m := mins/60, mins%60
	switch {
	case h == 0:
		return strconv.Itoa(m) + "m"
	case m == 0:
		return strconv.Itoa(h) + "h"
	default:
		return strconv.Itoa(h) + "h" + strconv.Itoa(m) + "m"
	}
}
