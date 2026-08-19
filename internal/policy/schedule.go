package policy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This file adds scheduled blocks: enforcement that is active only during
// declared time windows, and that can be locked so it cannot be weakened before
// a deadline.
//
// The design keeps the enforcers untouched. A schedule does not change *how*
// anything is enforced, only *what* is enforced right now - so Config.ActiveAt
// resolves the schedule into an ordinary Config with the currently-inactive
// extensions marked disabled, and the existing enforce.Set applies that. Nothing
// downstream needs to know schedules exist.
//
// A config with no blocks behaves exactly as it did before: every enabled
// extension is enforced around the clock.

// MaxLockDuration caps how far ahead a block may be locked. A lock cannot be
// lifted early even with the password, so a typo in the year would otherwise
// leave someone's browsers locked for decades with no recourse short of
// uninstalling. Ninety days is far longer than any plausible commitment and
// short enough to be survivable.
const MaxLockDuration = 90 * 24 * time.Hour

// Window is one recurring time range in local time. Days lists the weekdays the
// window starts on ("mon" through "sun", or full names; empty means every day).
// Start and End are "HH:MM" in 24-hour local time.
//
// An End at or before Start means the window runs past midnight: "22:00" to
// "06:00" on "fri" covers Friday night through Saturday morning.
type Window struct {
	Days  []string `json:"days,omitempty"`
	Start string   `json:"start"`
	End   string   `json:"end"`
}

// Block is a named group of extensions enforced on a schedule, optionally locked
// until a deadline.
//
// Extensions lists the extension names the block governs; empty means every
// extension in the catalog. Windows empty means "always" - a block with no
// windows is simply an always-on group, which is what a lock alone needs.
//
// LockedUntil is an RFC 3339 timestamp. While it is in the future the block
// cannot be weakened or removed, even by someone holding the uninstall password.
// That is the whole promise of a commitment tool, and it is why MaxLockDuration
// exists.
type Block struct {
	ID          string   `json:"id"`
	Label       string   `json:"label,omitempty"`
	Extensions  []string `json:"extensions,omitempty"`
	Windows     []Window `json:"windows,omitempty"`
	LockedUntil string   `json:"lockedUntil,omitempty"`
}

// parseHM turns "09:00" into minutes since midnight.
func parseHM(s string) (int, bool) {
	h, m, found := strings.Cut(strings.TrimSpace(s), ":")
	if !found {
		return 0, false
	}
	hh, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || hh < 0 || hh > 23 {
		return 0, false
	}
	mm, err := strconv.Atoi(strings.TrimSpace(m))
	if err != nil || mm < 0 || mm > 59 {
		return 0, false
	}
	return hh*60 + mm, true
}

// weekdayNames maps the accepted spellings to a weekday.
var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "sunday": time.Sunday,
	"mon": time.Monday, "monday": time.Monday,
	"tue": time.Tuesday, "tues": time.Tuesday, "tuesday": time.Tuesday,
	"wed": time.Wednesday, "weds": time.Wednesday, "wednesday": time.Wednesday,
	"thu": time.Thursday, "thur": time.Thursday, "thurs": time.Thursday, "thursday": time.Thursday,
	"fri": time.Friday, "friday": time.Friday,
	"sat": time.Saturday, "saturday": time.Saturday,
}

func parseWeekday(s string) (time.Weekday, bool) {
	d, ok := weekdayNames[strings.ToLower(strings.TrimSpace(s))]
	return d, ok
}

// coversDay reports whether the window may start on the given weekday. No days
// listed means every day.
func (w Window) coversDay(d time.Weekday) bool {
	if len(w.Days) == 0 {
		return true
	}
	for _, name := range w.Days {
		if got, ok := parseWeekday(name); ok && got == d {
			return true
		}
	}
	return false
}

// Active reports whether at falls inside this window, evaluated in at's own
// location.
//
// A window whose End is at or before its Start runs past midnight, so the check
// has two halves: the tail of a window that started today, and the head of one
// that started yesterday.
func (w Window) Active(at time.Time) bool {
	start, okStart := parseHM(w.Start)
	end, okEnd := parseHM(w.End)
	if !okStart || !okEnd {
		return false // unparseable window enforces nothing; Validate reports it
	}
	mins := at.Hour()*60 + at.Minute()

	if start < end {
		return w.coversDay(at.Weekday()) && mins >= start && mins < end
	}
	if start == end {
		return false // zero-length; Validate rejects it
	}
	// Overnight: the tail of today's window...
	if w.coversDay(at.Weekday()) && mins >= start {
		return true
	}
	// ...and the head belonging to yesterday's.
	yesterday := time.Weekday((int(at.Weekday()) + 6) % 7)
	return w.coversDay(yesterday) && mins < end
}

// Active reports whether the block is enforcing at the given time. A block with
// no windows is always active.
func (b Block) Active(at time.Time) bool {
	if len(b.Windows) == 0 {
		return true
	}
	for _, w := range b.Windows {
		if w.Active(at) {
			return true
		}
	}
	return false
}

// LockedAt reports whether the block is locked against weakening at the given
// time, and until when. An unparseable LockedUntil counts as locked: a corrupted
// deadline must not silently become "not locked", which would turn a bad edit
// into a bypass.
func (b Block) LockedAt(at time.Time) (bool, time.Time) {
	if strings.TrimSpace(b.LockedUntil) == "" {
		return false, time.Time{}
	}
	until, err := time.Parse(time.RFC3339, b.LockedUntil)
	if err != nil {
		return true, time.Time{}
	}
	return at.Before(until), until
}

// Governs reports whether this block covers the named extension. A block with no
// extensions listed governs every extension in the catalog.
func (b Block) Governs(name string) bool {
	if len(b.Extensions) == 0 {
		return true
	}
	name = strings.ToLower(strings.TrimSpace(name))
	for _, e := range b.Extensions {
		if strings.ToLower(strings.TrimSpace(e)) == name {
			return true
		}
	}
	return false
}

// ActiveAt resolves the schedule into a plain Config describing what should be
// enforced at the given moment: an extension governed by a block is enabled only
// while one of its blocks is active, and an extension no block governs keeps its
// configured state.
//
// The returned Config is a copy; the receiver is untouched. A config with no
// blocks is returned unchanged, which is what keeps every pre-schedule install
// behaving exactly as before.
func (c Config) ActiveAt(at time.Time) Config {
	if len(c.Blocks) == 0 {
		return c
	}
	out := c
	out.Extensions = make([]Extension, len(c.Extensions))
	copy(out.Extensions, c.Extensions)

	for i, e := range out.Extensions {
		if e.Disabled {
			continue // switched off outright; a schedule does not resurrect it
		}
		governed, active := false, false
		for _, b := range c.Blocks {
			if !b.Governs(e.Name) {
				continue
			}
			governed = true
			if b.Active(at) {
				active = true
				break
			}
		}
		if governed && !active {
			out.Extensions[i].Disabled = true
		}
	}
	return out
}

// EnforcedAt resolves the schedule into the config that should be enforced at
// the given moment, and reports any validation problem that stopped it.
//
// An invalid schedule fails closed. A window that will not parse makes its block
// look inactive, which would quietly switch enforcement off for every extension
// that block governs - the opposite of what the config's author asked for. So a
// config that does not validate is returned with its schedule ignored, meaning
// everything enabled stays enforced until the schedule is corrected. Callers
// surface the returned error; they must not treat it as a reason to enforce less.
func (c Config) EnforcedAt(at time.Time) (Config, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c.ActiveAt(at), nil
}

// ActiveSignature is a stable description of what ActiveAt would enforce at the
// given time. The service compares it between ticks to notice a schedule
// boundary without touching the registry.
func (c Config) ActiveSignature(at time.Time) string {
	active := c.ActiveAt(at)
	names := make([]string, 0, len(active.Extensions))
	for _, e := range active.Extensions {
		if !e.Disabled {
			names = append(names, strings.ToLower(e.Name))
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// Block returns the block with the given id (case-insensitive).
func (c Config) Block(id string) (Block, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, b := range c.Blocks {
		if strings.ToLower(b.ID) == id {
			return b, true
		}
	}
	return Block{}, false
}

// LockedBlocks returns the blocks locked against weakening at the given time.
func (c Config) LockedBlocks(at time.Time) []Block {
	var out []Block
	for _, b := range c.Blocks {
		if locked, _ := b.LockedAt(at); locked {
			out = append(out, b)
		}
	}
	return out
}

// Validate reports the first problem that would make a config behave in a way
// its author did not intend. It is deliberately strict about schedules: a window
// that silently never fires is worse than a config that refuses to load, because
// the user believes they are protected when they are not.
func (c Config) Validate() error {
	seen := make(map[string]bool, len(c.Blocks))
	known := make(map[string]bool, len(c.Extensions))
	for _, e := range c.Extensions {
		known[strings.ToLower(strings.TrimSpace(e.Name))] = true
	}

	for _, b := range c.Blocks {
		id := strings.ToLower(strings.TrimSpace(b.ID))
		if id == "" {
			return fmt.Errorf("a block has no id")
		}
		if seen[id] {
			return fmt.Errorf("duplicate block id %q", b.ID)
		}
		seen[id] = true

		for _, name := range b.Extensions {
			if !known[strings.ToLower(strings.TrimSpace(name))] {
				return fmt.Errorf("block %q lists unknown extension %q", b.ID, name)
			}
		}

		for i, w := range b.Windows {
			start, okStart := parseHM(w.Start)
			end, okEnd := parseHM(w.End)
			if !okStart {
				return fmt.Errorf("block %q window %d: bad start time %q (want HH:MM)", b.ID, i, w.Start)
			}
			if !okEnd {
				return fmt.Errorf("block %q window %d: bad end time %q (want HH:MM)", b.ID, i, w.End)
			}
			if start == end {
				return fmt.Errorf("block %q window %d: start and end are both %q, so it never applies", b.ID, i, w.Start)
			}
			for _, d := range w.Days {
				if _, ok := parseWeekday(d); !ok {
					return fmt.Errorf("block %q window %d: unknown day %q", b.ID, i, d)
				}
			}
		}

		if s := strings.TrimSpace(b.LockedUntil); s != "" {
			until, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return fmt.Errorf("block %q: lockedUntil %q is not an RFC 3339 timestamp", b.ID, s)
			}
			if d := time.Until(until); d > MaxLockDuration {
				return fmt.Errorf("block %q: lockedUntil is %s away, more than the %s maximum",
					b.ID, d.Round(time.Hour), MaxLockDuration)
			}
		}
	}
	return nil
}

// CheckLockedBlocks reports why proposed may not replace current, given the
// blocks locked at now. A locked block is the one promise this tool makes that
// the password cannot override, so the rule is deliberately blunt: while a block
// is locked it is immutable, except that its deadline may be pushed further out.
//
// Being blunt is the point. A subtler rule - "the schedule may change as long as
// it does not narrow" - means computing whether one set of time windows covers
// another, and any gap in that reasoning is a way out of a commitment someone
// made specifically because they did not trust their future self. Refusing every
// edit is easy to verify and easy to explain.
//
// Adding a block, or locking one that was not locked, is always allowed: those
// strengthen.
func CheckLockedBlocks(current, proposed Config, now time.Time) error {
	for _, old := range current.Blocks {
		locked, until := old.LockedAt(now)
		if !locked {
			continue
		}
		deadline := "an unreadable deadline"
		if !until.IsZero() {
			deadline = until.Local().Format(time.RFC1123)
		}

		next, ok := proposed.Block(old.ID)
		if !ok {
			return fmt.Errorf("block %q is locked until %s and cannot be removed", old.ID, deadline)
		}
		if !sameExceptDeadline(old, next) {
			return fmt.Errorf("block %q is locked until %s and cannot be changed until then", old.ID, deadline)
		}
		if shortensLock(old, next) {
			return fmt.Errorf("block %q is locked until %s; a lock can be extended but not shortened", old.ID, deadline)
		}
	}
	return nil
}

// sameExceptDeadline compares two versions of a block ignoring LockedUntil.
func sameExceptDeadline(a, b Block) bool {
	a.LockedUntil, b.LockedUntil = "", ""
	if a.ID != b.ID || a.Label != b.Label {
		return false
	}
	if !sameStrings(a.Extensions, b.Extensions) || len(a.Windows) != len(b.Windows) {
		return false
	}
	for i := range a.Windows {
		if a.Windows[i].Start != b.Windows[i].Start || a.Windows[i].End != b.Windows[i].End {
			return false
		}
		if !sameStrings(a.Windows[i].Days, b.Windows[i].Days) {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(strings.TrimSpace(a[i]), strings.TrimSpace(b[i])) {
			return false
		}
	}
	return true
}

// shortensLock reports whether next would bring a locked block's deadline
// forward - including removing it, or replacing it with something unreadable.
func shortensLock(old, next Block) bool {
	oldUntil, err := time.Parse(time.RFC3339, strings.TrimSpace(old.LockedUntil))
	if err != nil {
		// An unreadable current deadline counts as locked (see LockedAt), so the
		// only safe move is to require a readable one that is genuinely in future.
		nextUntil, nErr := time.Parse(time.RFC3339, strings.TrimSpace(next.LockedUntil))
		return nErr != nil || !nextUntil.After(time.Now())
	}
	nextUntil, err := time.Parse(time.RFC3339, strings.TrimSpace(next.LockedUntil))
	if err != nil {
		return true // removed or corrupted
	}
	return nextUntil.Before(oldUntil)
}
