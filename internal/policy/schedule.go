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
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	// Extensions, Domains and Apps are what the block governs. Naming none of them
	// means the block governs everything in every catalog; naming any means it
	// governs exactly what is listed, and nothing of the kinds it leaves out. That
	// keeps a pre-domains (and pre-apps) config reading the same way it always did.
	//
	// Apps are listed by the value the rule is stored under - an executable path
	// or name, a folder, a Store package family name, or a window title.
	Extensions []string `json:"extensions,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	Apps       []string `json:"apps,omitempty"`
	Windows    []Window `json:"windows,omitempty"`
	// Limit is a daily budget: how long the applications this block covers may be
	// used before it starts enforcing. Empty means no limit, which is what every
	// block written before limits existed says. "45m", "1h30m" and "45" all read as
	// you would expect - see limits.go, which is also where the reasons a limit may
	// only cover applications are set out.
	Limit       string `json:"limit,omitempty"`
	LockedUntil string `json:"lockedUntil,omitempty"`
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

// InWindow reports whether the given time falls in one of the block's windows. A
// block with no windows is in window always.
//
// This is not the same question as "is it enforcing": a block may also carry a
// daily limit, and while that limit has budget left the block is in window and
// enforcing nothing. EnforcingAt is the question with both halves - see limits.go.
func (b Block) InWindow(at time.Time) bool {
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

// governsAll reports whether the block covers every catalog wholesale, which is
// what naming no extensions, domains or apps means.
func (b Block) governsAll() bool {
	return len(b.Extensions) == 0 && len(b.Domains) == 0 && len(b.Apps) == 0
}

// Governs reports whether this block covers the named extension.
func (b Block) Governs(name string) bool {
	if b.governsAll() {
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

// GovernsDomain reports whether this block covers the named domain, comparing
// normalized hosts so the block list and the catalog agree on what "reddit.com"
// means however either was typed.
func (b Block) GovernsDomain(name string) bool {
	if b.governsAll() {
		return true
	}
	want, err := NormalizeDomain(name)
	if err != nil {
		return false
	}
	for _, d := range b.Domains {
		if h, err := NormalizeDomain(d); err == nil && h == want {
			return true
		}
	}
	return false
}

// GovernsApp reports whether this block covers an app rule, comparing normalized
// values so the block list and the catalog agree on what a path or package name
// means however either was typed.
func (b Block) GovernsApp(a App) bool {
	if b.governsAll() {
		return true
	}
	want, err := NormalizeApp(a.Kind, a.Value, "")
	if err != nil {
		return false
	}
	for _, listed := range b.Apps {
		// A block lists an app by value, not by kind: the kind is a property of the
		// catalog entry, and repeating it in the schedule would be a second place to
		// get it wrong. So the listed value is normalized as the entry's own kind.
		if n, err := NormalizeApp(a.Kind, listed, ""); err == nil && n.key() == want.key() {
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
// It reads today's usage from the ledger to decide the blocks that carry a limit
// (see Config.SpentAt). Callers holding fresher counters than the ledger has -
// which means the service - should use ActiveAtWith instead, so that a budget
// crossed seconds ago is not resolved against a file that has yet to be flushed.
func (c Config) ActiveAt(at time.Time) Config {
	return c.ActiveAtWith(at, c.SpentAt(at))
}

// ActiveAtWith is ActiveAt against a given set of spent budgets.
//
// The returned Config is a copy; the receiver is untouched. A config with no
// blocks is returned unchanged, which is what keeps every pre-schedule install
// behaving exactly as before.
func (c Config) ActiveAtWith(at time.Time, sp Spent) Config {
	if len(c.Blocks) == 0 {
		return c
	}
	out := c
	out.Extensions = make([]Extension, len(c.Extensions))
	copy(out.Extensions, c.Extensions)
	out.Domains = make([]Domain, len(c.Domains))
	copy(out.Domains, c.Domains)
	out.Apps = make([]App, len(c.Apps))
	copy(out.Apps, c.Apps)

	for i, e := range out.Extensions {
		if e.Disabled {
			continue // switched off outright; a schedule does not resurrect it
		}
		if c.notEnforced(at, sp, func(b Block) bool { return b.Governs(e.Name) }) {
			out.Extensions[i].Disabled = true
		}
	}
	for i, d := range out.Domains {
		if d.Disabled {
			continue
		}
		if c.notEnforced(at, sp, func(b Block) bool { return b.GovernsDomain(d.Name) }) {
			out.Domains[i].Disabled = true
		}
	}
	for i, a := range out.Apps {
		if a.Disabled {
			continue
		}
		if c.notEnforced(at, sp, func(b Block) bool { return b.GovernsApp(a) }) {
			out.Apps[i].Disabled = true
		}
	}
	return out
}

// notEnforced reports whether an entry that is switched on should nonetheless be
// treated as off at this moment: some block governs it, and none of the blocks
// governing it is enforcing. An entry no block governs is always enforced - around
// the clock, which is what a config with no schedule means.
//
// The union is what makes several blocks over one entry safe: it is enforced if
// *any* block governing it is enforcing, so adding a block can only ever add
// enforced time. That is also why a limit reaching zero blocks rather than
// releases - it makes the block start enforcing, and the union grows.
func (c Config) notEnforced(at time.Time, sp Spent, governs func(Block) bool) bool {
	governed := false
	for _, b := range c.Blocks {
		if !governs(b) {
			continue
		}
		if b.EnforcingAt(at, sp) {
			return false
		}
		governed = true
	}
	return governed
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
	return c.EnforcedAtWith(at, c.SpentAt(at))
}

// EnforcedAtWith is EnforcedAt against a given set of spent budgets.
func (c Config) EnforcedAtWith(at time.Time, sp Spent) (Config, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c.ActiveAtWith(at, sp), nil
}

// ActiveSignature is a stable description of what ActiveAt would enforce at the
// given time. The service compares it between ticks to notice a schedule
// boundary without touching the registry.
func (c Config) ActiveSignature(at time.Time) string {
	return c.ActiveSignatureWith(at, c.SpentAt(at))
}

// ActiveSignatureWith is ActiveSignature against a given set of spent budgets.
// This is how a limit running out becomes enforcement within a second: the
// signature changes, and the service re-applies on the change exactly as it does
// for a window opening.
func (c Config) ActiveSignatureWith(at time.Time, sp Spent) string {
	active := c.ActiveAtWith(at, sp)
	names := make([]string, 0, len(active.Extensions)+len(active.Domains)+len(active.Apps))
	for _, e := range active.Extensions {
		if !e.Disabled {
			names = append(names, "ext:"+strings.ToLower(e.Name))
		}
	}
	for _, d := range active.BlockedDomains() {
		names = append(names, "dom:"+d)
	}
	for _, a := range active.BlockedApps() {
		names = append(names, "app:"+a.key())
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// Narrows reports whether this block makes enforcement *less* than around the
// clock for whatever it governs - which is exactly what having windows, or a
// daily budget, means.
//
// This is the load-bearing fact behind the gate on creating one. Everywhere else
// in the guard, adding a rule strengthens protection and costs only admin, while
// weakening it costs the password. A schedule inverts that: putting an extension
// that was enforced continuously onto a 09:00-17:00 timetable *un*-enforces it for
// sixteen hours a day. So a block with windows needs the password, and a block
// without them - the always-on kind that exists to be locked - does not.
//
// The rule is deliberately blunt in the same way CheckLockedBlocks is. A precise
// answer would mean computing whether the new block's windows cover what some
// other block already covers, and that is the window-coverage reasoning this file
// refuses to do, because any gap in it is a way out of a commitment.
//
// A limit narrows for the same reason a window does, and more obviously: an app
// that was blocked outright becomes an app you may use for forty-five minutes.
func (b Block) Narrows() bool { return len(b.Windows) > 0 || b.HasLimit() }

// AddBlock appends a block, refusing an id that is already taken. The caller is
// expected to Validate afterwards: this checks only what is about the collection
// rather than about the block itself.
func (c *Config) AddBlock(b Block) error {
	id := strings.ToLower(strings.TrimSpace(b.ID))
	if id == "" {
		return fmt.Errorf("a block needs an id")
	}
	if _, exists := c.Block(id); exists {
		return fmt.Errorf("there is already a block called %q", b.ID)
	}
	c.Blocks = append(c.Blocks, b)
	return nil
}

// RemoveBlock drops the block with the given id, reporting whether it was there.
// Whether removal is *allowed* is not decided here - a locked block is refused by
// CheckLockedBlocks, which compares the whole config and is what every mutation
// path already goes through.
func (c *Config) RemoveBlock(id string) bool {
	want := strings.ToLower(strings.TrimSpace(id))
	for i, b := range c.Blocks {
		if strings.ToLower(b.ID) == want {
			c.Blocks = append(c.Blocks[:i], c.Blocks[i+1:]...)
			return true
		}
	}
	return false
}

// ReplaceBlock swaps the block carrying b's id for b, reporting whether one was
// there to replace. Like RemoveBlock it does not decide whether the change is
// allowed: CheckLockedBlocks compares the whole config on the way out and is
// what refuses a replacement that would weaken a locked block.
func (c *Config) ReplaceBlock(b Block) bool {
	want := strings.ToLower(strings.TrimSpace(b.ID))
	for i := range c.Blocks {
		if strings.ToLower(c.Blocks[i].ID) == want {
			c.Blocks[i] = b
			return true
		}
	}
	return false
}

// NewBlockID derives a block id from a label, keeping it short, lowercase and
// free of anything that would need quoting on a command line - the id is what
// `guard lock` and `guard remove-block` take as an argument. A collision gets a
// numeric suffix, so a second "Work hours" becomes "work-hours-2".
//
// This exists so the status window can ask for a name and nothing else. Making a
// person invent a stable identifier for something they think of as "evenings" is
// the kind of detail that stops a feature from being used.
func NewBlockID(label string, taken func(string) bool) string {
	var b strings.Builder
	lastDash := true // suppresses a leading dash
	for _, r := range strings.ToLower(strings.TrimSpace(label)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	id := strings.Trim(b.String(), "-")
	if len(id) > 24 {
		id = strings.Trim(id[:24], "-")
	}
	if id == "" {
		id = "block"
	}
	if taken == nil || !taken(id) {
		return id
	}
	for n := 2; ; n++ {
		candidate := id + "-" + strconv.Itoa(n)
		if !taken(candidate) {
			return candidate
		}
	}
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
	if err := c.validateDomains(); err != nil {
		return err
	}
	if err := c.validateApps(); err != nil {
		return err
	}
	if err := c.validateLimits(); err != nil {
		return err
	}
	if err := c.validateHardening(); err != nil {
		return err
	}
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
		for _, name := range b.Domains {
			host, err := NormalizeDomain(name)
			if err != nil {
				return fmt.Errorf("block %q: %w", b.ID, err)
			}
			if !c.HasDomain(host) {
				return fmt.Errorf("block %q lists domain %q, which is not in the domains list", b.ID, host)
			}
		}
		for _, value := range b.Apps {
			// The kind is not repeated in the block, so a listed value has to match
			// some catalog entry under that entry's own kind. Checking it here is what
			// stops a typo from silently governing nothing - which would leave the app
			// blocked around the clock while the schedule looks like it applies.
			if !c.appListed(value) {
				return fmt.Errorf("block %q lists app %q, which is not in the apps list", b.ID, value)
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
	if !sameStrings(a.Extensions, b.Extensions) {
		return false
	}
	// Domains are compared normalized, so rewriting "reddit.com" as
	// "https://www.Reddit.com/" is not treated as a change while actually adding or
	// dropping a site still is.
	if !sameDomains(a.Domains, b.Domains) {
		return false
	}
	// Apps are compared the same way: case and slash direction do not change which
	// application a path names, so rewriting one is not an edit, while swapping in
	// a different app is.
	if !sameApps(a.Apps, b.Apps) {
		return false
	}
	// The limit is compared as a length of time rather than as text, so rewriting
	// "90m" as "1h30m" is not an edit while raising the budget is. This comparison
	// is the reason a lock means anything to a limit at all: without it, a block
	// locked for a week could have its forty-five minutes a day quietly turned into
	// ten hours, which is every bit as much a release as deleting the block.
	if aLimit, bLimit := a.limitOrZero(), b.limitOrZero(); aLimit != bLimit {
		return false
	}
	if len(a.Windows) != len(b.Windows) {
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

// sameDomains compares two domain lists by their normalized hosts.
func sameDomains(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	norm := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, s := range in {
			if h, err := NormalizeDomain(s); err == nil {
				out = append(out, h)
			} else {
				out = append(out, strings.ToLower(strings.TrimSpace(s)))
			}
		}
		sort.Strings(out)
		return out
	}
	return sameOrderStrings(norm(a), norm(b))
}

// sameApps compares two app lists by their comparable form: backslashes and
// case do not distinguish two paths, so neither should they distinguish two
// versions of a locked block.
func sameApps(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	norm := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, s := range in {
			out = append(out, strings.ToLower(normalizeWinPath(s)))
		}
		sort.Strings(out)
		return out
	}
	return sameOrderStrings(norm(a), norm(b))
}

func sameOrderStrings(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
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

// weekdayOrder is Monday-first, which is how a schedule reads to a person even
// though time.Weekday starts at Sunday.
var weekdayOrder = []time.Weekday{
	time.Monday, time.Tuesday, time.Wednesday, time.Thursday,
	time.Friday, time.Saturday, time.Sunday,
}

var weekdayShort = map[time.Weekday]string{
	time.Monday: "Mon", time.Tuesday: "Tue", time.Wednesday: "Wed", time.Thursday: "Thu",
	time.Friday: "Fri", time.Saturday: "Sat", time.Sunday: "Sun",
}

// daysSummary renders a window's days the way a person would say them.
func (w Window) daysSummary() string {
	if len(w.Days) == 0 {
		return "Daily"
	}
	set := make(map[time.Weekday]bool, len(w.Days))
	for _, d := range w.Days {
		if wd, ok := parseWeekday(d); ok {
			set[wd] = true
		}
	}
	switch {
	case len(set) == 0:
		return "Never" // every entry was unparseable; Validate reports why
	case len(set) == 7:
		return "Daily"
	case len(set) == 5 && !set[time.Saturday] && !set[time.Sunday]:
		return "Mon-Fri"
	case len(set) == 2 && set[time.Saturday] && set[time.Sunday]:
		return "Weekends"
	}
	names := make([]string, 0, len(set))
	for _, wd := range weekdayOrder {
		if set[wd] {
			names = append(names, weekdayShort[wd])
		}
	}
	return strings.Join(names, " ")
}

// Summary renders one window as "Mon-Fri 09:00-17:00".
func (w Window) Summary() string {
	return w.daysSummary() + " " + strings.TrimSpace(w.Start) + "-" + strings.TrimSpace(w.End)
}

// ScheduleSummary renders the block's windows for display. A block with no
// windows is always on, which is what a lock alone needs.
func (b Block) ScheduleSummary() string {
	if len(b.Windows) == 0 {
		return "Always"
	}
	parts := make([]string, 0, len(b.Windows))
	for _, w := range b.Windows {
		parts = append(parts, w.Summary())
	}
	return strings.Join(parts, ", ")
}

// GovernedSummary names what the block governs, for display. A block naming no
// list governs every catalog, which is what "everything" means here.
func (b Block) GovernedSummary() string {
	if b.governsAll() {
		return "everything"
	}
	parts := make([]string, 0, len(b.Extensions)+len(b.Domains)+len(b.Apps))
	parts = append(parts, b.Extensions...)
	for _, d := range b.Domains {
		if h, err := NormalizeDomain(d); err == nil {
			parts = append(parts, h)
		} else {
			parts = append(parts, d)
		}
	}
	for _, a := range b.Apps {
		// Shown as the leaf name: a block row is one line, and a full install path
		// would push everything else off it.
		parts = append(parts, baseName(normalizeWinPath(a)))
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, ", ")
}

// GovernedBy reports whether any block in the config governs the named
// extension - that is, whether its enforcement is on a schedule rather than
// around the clock.
func (c Config) GovernedBy(name string) bool {
	for _, b := range c.Blocks {
		if b.Governs(name) {
			return true
		}
	}
	return false
}

// CheckPausable reports why protection may not be paused at now.
//
// CheckLockedBlocks cannot answer this, because a pause is not a config edit:
// nothing about the config changes, enforcement simply stops. The effect on a
// locked block is total all the same - a pause tears the service down and lifts
// everything it was holding - so a lock has to refuse it. Otherwise "locked until
// Friday" means "locked until somebody types the password and pauses", which is
// not a commitment, and the lock is the one promise this tool makes that the
// password is not supposed to override.
//
// Uninstalling stays allowed, deliberately, and the difference is worth being
// precise about rather than leaving as an apparent inconsistency. An uninstall is
// the documented escape hatch (see docs/pc-version.md: software that cannot be
// removed at all is malware). It lifts every enforcement, clears the password and
// the trusted config, takes the blocks with it, and leaves an entry in the
// activity log. A pause is none of those things - it is quiet, reversible, and
// leaves the commitment nominally in place during exactly the window it is not
// being kept. Refusing the quiet way out while keeping the loud one is the point:
// there is still a way out, and it costs the install rather than a keystroke.
//
// Blunt in the same way CheckLockedBlocks is: any live lock refuses the pause. A
// pause turns everything off, so there is no narrower version of the question to
// ask.
func CheckPausable(cfg Config, now time.Time) error {
	for _, b := range cfg.Blocks {
		locked, until := b.LockedAt(now)
		if !locked {
			continue
		}
		deadline := "an unreadable deadline"
		if !until.IsZero() {
			deadline = until.Local().Format(time.RFC1123)
		}
		return fmt.Errorf("block %q is locked until %s, so protection cannot be paused until then", b.ID, deadline)
	}
	return nil
}
