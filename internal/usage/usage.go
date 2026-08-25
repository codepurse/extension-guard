// Package usage is the guard's ledger of how long each limited block has been
// used today. It is what makes a time limit possible.
//
// Why it exists. Everything else in the guard is a rule about *when* something is
// enforced - a window, a lock, a deadline - and every one of those can be decided
// from the clock alone. A limit is a rule about *how much*, and there is no way
// to answer "has this had its forty-five minutes?" without a count that outlives
// the process doing the counting. A limit whose counter resets when the machine
// reboots is not a limit; it is a suggestion.
//
// Why the count does not live in the config. extension-ids.json describes intent,
// and the guard treats it as untrusted precisely because intent must not be
// editable behind its back: every cycle it is reconciled against a trusted copy
// and rewritten to match (see internal/policy/trust.go). A counter that changed
// every second inside that file would either be reverted as tamper or force the
// trusted copy to be re-recorded constantly, which would make "the config was
// changed" mean nothing. A measurement is not a policy, and it does not belong in
// the document that states one.
//
// Shape: one small JSON object, rewritten in place rather than appended to. That
// is the opposite of the activity log next to it, and deliberately so - the log
// exists so that no single entry can be removed, while this exists so that one
// number is current. A rewrite is staged in a temp file and renamed into place, so
// a reader never sees half a ledger.
//
// Permissions (Windows; see store_windows.go): SYSTEM and Administrators get full
// control, Users get read and nothing else.
//
//   - Read, because the status window runs unprivileged and has to be able to say
//     "23 of 45 minutes used" without asking for elevation. Being able to see how
//     much is left is most of the difference between a limit and an ambush.
//   - Not append, which the activity log does grant. That grant exists there for
//     one unprivileged writer - the refused-launch handler - and there is no
//     equivalent here. Anyone who could append to this file could make it
//     unparseable, and while that fails closed (policy reads an unreadable ledger
//     as every limit spent) it would still be a way to make the feature behave
//     strangely on purpose.
//
// What this does not close, stated plainly: an administrator can delete the file,
// and a missing file means a day with nothing spent yet - because that is exactly
// what a fresh install looks like, and the two are indistinguishable from here.
// That is the same class of hole as stopping the service, and it is answered the
// same way: by the watchdog, and by the fact that it has to be done again every
// day, rather than by pretending a user-space file can be beyond an
// administrator's reach.
package usage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// State says how far to trust what Load found. The distinction between "there is
// no ledger" and "there is one and it is broken" is load-bearing: the first is a
// fresh install with nothing spent, and the second must not be read as one.
type State int

const (
	// StateFresh means no ledger exists yet, so nothing has been spent.
	StateFresh State = iota
	// StateOK means the ledger was read.
	StateOK
	// StateUnreadable means a ledger exists and could not be parsed. Callers fail
	// closed on it - see policy.Spent.
	StateUnreadable
)

func (s State) String() string {
	switch s {
	case StateOK:
		return "ok"
	case StateUnreadable:
		return "unreadable"
	default:
		return "fresh"
	}
}

const (
	fileName = "usage.json"
	// tempName is where a rewrite is staged. It sits in the same directory so the
	// rename stays within one volume, which is what makes it atomic.
	tempName = "usage.json.new"
	// keepDays is how many days of counters are retained. Only today's decides
	// anything; the rest are kept because "how much did I actually use this week"
	// is the obvious next question, and discarding the answer every night would
	// make it unanswerable later.
	keepDays = 14
	// maxCharge caps what a single observation can add. Observations are a second
	// apart, so this only matters when the gap is much larger than that: a busy
	// machine that ran late (charge it, the app really was running) or one that was
	// asleep for eight hours (do not, it was not). The two are indistinguishable
	// from here, so the cap takes the honest side of the difference and keeps the
	// error down to seconds.
	maxCharge = 15 * time.Second
)

var (
	// dir is where the ledger lives. A var so tests can point it somewhere other
	// than the real ProgramData directory.
	dir = defaultDir()

	// ensureFile and secureFile are reached through vars for the same reason
	// internal/activity does it: the real ones stamp a protected DACL, and a test
	// that applied that to its own temp directory could not clean it up again
	// afterwards. store_windows_test.go exercises the real ones directly.
	ensureFile = ensure
	secureFile = secure
)

// Ledger is the whole file: seconds spent per block, per day.
//
// Days is keyed by a day string the caller computes, because where a day starts
// is a configured thing (policy.Config.ResetAt) and this package has no business
// knowing about it. The keys are plain "2006-01-02" dates, which sort as strings -
// LastDay depends on that.
//
// LastDay is the latest day this ledger has ever recorded, and it is the guard
// against the clock being wound back. Without it, setting the date to yesterday
// would hand back yesterday's unspent budget; with it, a day earlier than LastDay
// is served as LastDay instead, so time spent today stays spent whatever the clock
// says afterwards.
type Ledger struct {
	Days    map[string]map[string]int `json:"days"`
	LastDay string                    `json:"lastDay,omitempty"`
}

// Path is the ledger's full path. Exported so the CLI and the window can point at
// it rather than describing it vaguely.
func Path() string { return filepath.Join(dir, fileName) }

// Provision creates the ledger's directory and stamps its permissions. Only
// privileged code may call it - the service, and the elevated commands that
// establish protection - for the same reason internal/activity separates creation
// from use: ProgramData lets ordinary users create subdirectories, and a file an
// unprivileged process created would be owned by that user, who then holds
// WRITE_DAC over it however the DACL reads.
//
// It is idempotent, and it never truncates a ledger that is already there.
func Provision() error { return ensureFile(dir, Path()) }

// Load reads the ledger. It needs no privileges, so the status window and the CLI
// call it directly.
func Load() (Ledger, State) {
	data, err := os.ReadFile(Path())
	if err != nil {
		return Ledger{}, StateFresh
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		// A zero-length file is what an interrupted write leaves behind. Reading it
		// as fresh rather than as broken is deliberate: there is no number in it to
		// protect, so failing closed here would punish a torn write of ours rather
		// than an edit of somebody else's.
		return Ledger{}, StateFresh
	}
	var l Ledger
	if err := json.Unmarshal(data, &l); err != nil {
		return Ledger{}, StateUnreadable
	}
	return l, StateOK
}

// Spent returns what has been spent on the given day, per block, read straight
// from disk. This is the unprivileged read path: the status window and
// `guard limits` use it, and so does policy whenever it has no live counters of
// its own.
func Spent(day string) (map[string]time.Duration, State) {
	l, state := Load()
	return l.Spent(day), state
}

// Spent returns one day's counters as durations, resolving the day through the
// clock-rollback guard.
func (l Ledger) Spent(day string) map[string]time.Duration {
	counts := l.Days[l.effectiveDay(day)]
	out := make(map[string]time.Duration, len(counts))
	for id, secs := range counts {
		out[id] = time.Duration(secs) * time.Second
	}
	return out
}

// effectiveDay is the clock-rollback guard: never serve a day earlier than the
// latest one recorded. Day keys are dates, so comparing them as strings compares
// them chronologically.
func (l Ledger) effectiveDay(day string) string {
	if l.LastDay != "" && day < l.LastDay {
		return l.LastDay
	}
	return day
}

// add charges seconds to one block on one day, advancing LastDay. It refuses to
// write into a day earlier than the latest recorded, so time cannot be un-spent by
// moving the clock back.
func (l *Ledger) add(day, id string, seconds int) {
	if seconds <= 0 {
		return
	}
	id = Key(id)
	if id == "" {
		return
	}
	day = l.effectiveDay(day)
	if l.Days == nil {
		l.Days = map[string]map[string]int{}
	}
	if l.Days[day] == nil {
		l.Days[day] = map[string]int{}
	}
	l.Days[day][id] += seconds
	if day > l.LastDay {
		l.LastDay = day
	}
}

// prune drops all but the most recent keepDays days, so the file cannot grow
// without bound on a machine that has had a limit configured for years.
func (l *Ledger) prune() {
	if len(l.Days) <= keepDays {
		return
	}
	days := make([]string, 0, len(l.Days))
	for d := range l.Days {
		days = append(days, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(days)))
	for _, d := range days[keepDays:] {
		delete(l.Days, d)
	}
}

// save rewrites the ledger: a temp file, its permissions stamped before anything
// else can see it, then a rename over the real one.
//
// The order matters. A rename replaces the target's security descriptor with the
// source's, so stamping the final path afterwards would leave a window in which
// the ledger carried whatever the temp file had inherited. Stamp first, then
// publish.
func (l Ledger) save() error {
	l.prune()
	data, err := json.Marshal(l)
	if err != nil {
		return fmt.Errorf("encode usage: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create usage directory: %w", err)
	}
	tmp := filepath.Join(dir, tempName)
	if err := writeTemp(tmp, append(data, '\n')); err != nil {
		return fmt.Errorf("write usage: %w", err)
	}
	if err := secureFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("secure usage: %w", err)
	}
	if err := os.Rename(tmp, Path()); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace usage: %w", err)
	}
	return nil
}

// writeTemp writes the staging file, removing anything already sitting at that
// path if the write is refused.
//
// The retry is for one specific move. The staging path is predictable, and until
// the guard has been installed the directory it sits in inherits ProgramData's
// grant that lets ordinary users create files there. Somebody who gets in first
// can leave a file of their own at that name and, as its owner, deny even SYSTEM
// the right to write it - which would stop every flush from then on and freeze the
// counters wherever they stood. Deleting it first costs one syscall in the case
// that never happens.
func writeTemp(path string, data []byte) error {
	err := os.WriteFile(path, data, 0o644)
	if err == nil {
		return err
	}
	if rmErr := os.Remove(path); rmErr != nil {
		return err // report the write failure, which is the one that matters
	}
	return os.WriteFile(path, data, 0o644)
}

// Key normalizes a block id into the form the ledger files it under. Block ids are
// compared case-insensitively everywhere else in the guard, and a counter stored
// under "Games" that nothing ever looks up as "games" is a limit that never fires.
func Key(id string) string { return strings.ToLower(strings.TrimSpace(id)) }

// Tracker is the writing half: the service's live counters, flushed to disk
// periodically rather than on every observation.
//
// Why not write every time. Observations happen once a second, and a file rewrite
// per second is 86,400 rewrites a day for a number that is only read when
// something crosses a limit. So the count is held in memory and flushed on an
// interval, which costs precision in exactly one situation - the machine losing
// power between flushes - and the cost is bounded by the flush interval. The
// service also flushes the moment a limit is crossed, because that is the one
// transition where the exact number matters.
type Tracker struct {
	mu    sync.Mutex
	led   Ledger
	state State
	dirty bool
	// last is when Observe last ran. Elapsed time is measured between observations
	// rather than assumed from the tick interval, so a tick that arrives late
	// charges what actually passed.
	last time.Time
	// carry is the fraction of a second left over from the last observation.
	//
	// It matters more than it looks. The ledger counts whole seconds, and a ticker
	// on a busy machine does not deliver neat one-second intervals - it delivers
	// 1.2s then 0.8s. Truncating each of those on its own charges one second for two
	// seconds of use, and an error that always rounds the same way is not noise, it
	// is a discount. Carrying the remainder keeps the total honest to within a
	// second.
	//
	// It is dropped whenever nothing is running, because an interval that charged
	// nothing has no remainder to owe. The cost is that a fraction accrued by one
	// block can be charged to another that starts immediately afterwards, which is
	// wrong by less than a second and only ever once.
	carry time.Duration
}

// NewTracker loads the ledger from disk and returns a tracker over it. Loading is
// the point: a service restart in the middle of the afternoon must not hand back
// the whole day's budget.
//
// An unreadable ledger is marked for rewriting straight away, and that is not a
// detail. While the state stands, every limit reads as spent (see policy.Spent),
// and a limited application is therefore blocked - which means it cannot run,
// which means nothing gets charged, which means nothing is ever flushed and the
// state never clears. Failing closed has to be a moment, not a trap: the caller
// flushes, the file becomes one that parses, and counting starts again from there.
//
// The counters that were in the damaged file are gone, and there is no honest way
// around that. Nor is much lost by admitting it: only SYSTEM and administrators can
// write this file at all, and anyone who can corrupt it can equally delete it,
// which has always read as a fresh day. What matters is that it leaves a mark - the
// service records the rebuild.
func NewTracker() *Tracker {
	led, state := Load()
	return &Tracker{led: led, state: state, dirty: state == StateUnreadable}
}

// State reports how the ledger was found. The service records an unreadable one in
// the activity log, because limits behave differently (they read as spent) until
// the next flush replaces the file.
func (t *Tracker) State() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// Observe charges the time since the previous call to every block in ids, and
// returns how much was charged. The first call establishes the baseline and
// charges nothing.
//
// A negative interval means the clock moved backwards. Nothing is charged for it,
// and the baseline is left where it was, so winding the clock back cannot make the
// next observation charge a negative or enormous amount.
func (t *Tracker) Observe(now time.Time, day string, ids []string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	elapsed := now.Sub(t.last)
	if t.last.IsZero() || elapsed < 0 {
		t.last = now
		return 0
	}
	if elapsed > maxCharge {
		elapsed = maxCharge
	}
	t.last = now

	if len(ids) == 0 {
		t.carry = 0 // nothing was running, so there is no remainder to owe
		return 0
	}
	t.carry += elapsed
	secs := int(t.carry / time.Second)
	if secs <= 0 {
		return 0 // less than a second so far; it is held in carry, not lost
	}
	t.carry -= time.Duration(secs) * time.Second
	for _, id := range ids {
		t.led.add(day, id, secs)
	}
	t.dirty = true
	return time.Duration(secs) * time.Second
}

// Spent returns the day's counters from the live in-memory ledger. The service
// resolves enforcement against this rather than re-reading the file, so a limit
// crossed since the last flush is honoured immediately.
func (t *Tracker) Spent(day string) map[string]time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.led.Spent(day)
}

// Flush writes the ledger if anything has changed. It is a no-op otherwise, so the
// caller can call it on a timer without thinking about it.
//
// A successful write also clears an unreadable state: whatever was in the file
// before, what is in it now is ours and parses.
func (t *Tracker) Flush() error {
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return nil
	}
	snapshot := t.led.clone()
	t.mu.Unlock()

	if err := snapshot.save(); err != nil {
		return err
	}

	t.mu.Lock()
	t.dirty = false
	t.state = StateOK
	t.mu.Unlock()
	return nil
}

// clone deep-copies the ledger so a flush can write without holding the lock
// across a file write - the observation every second matters more than the write
// every thirty.
func (l Ledger) clone() Ledger {
	out := Ledger{LastDay: l.LastDay, Days: make(map[string]map[string]int, len(l.Days))}
	for day, counts := range l.Days {
		day2 := make(map[string]int, len(counts))
		for id, secs := range counts {
			day2[id] = secs
		}
		out.Days[day] = day2
	}
	return out
}
