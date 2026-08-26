// Package activity is the guard's local activity log: an append-only record of
// what the guard did, and of what was done to the guard.
//
// Why it exists. Every other part of the guard answers "what is enforced right
// now" - the status window, `guard verify`, every Enforcer's Verify. None of them
// answer "what happened while nobody was watching", and for an accountability
// tool that is the more useful question. A blocked launch at two in the morning,
// a pause nobody lifted, a config edit the service reverted: each of those is
// invisible the moment it scrolls past. The Windows event log is not an answer
// either - it is not somewhere a parent will look, and it is not readable by the
// person being filtered, which the record about them should be.
//
// Shape: one JSON object per line, appended, never rewritten. An append is a
// single small write with no read-modify-write, so the writers that exist - the
// SYSTEM service, an elevated CLI, the session agent, the status window - need no
// coordination beyond the operating system's own append atomicity. It also means
// truncation is the only way to lose an entry, which is what the file permissions
// are for.
//
// Permissions, and what they do and do not buy (Windows; see store_windows.go):
//
//   - SYSTEM and Administrators get full control. The service writes as SYSTEM,
//     and the password-gated commands write elevated.
//   - Users get read, and append. Not write, not delete.
//
// Read is deliberate rather than a concession. The person being filtered is meant
// to be able to see the record kept about them; that transparency is part of what
// separates this from the stalkerware the README is at pains to distinguish it
// from. Append *is* a concession, and a narrow one: it is what lets a refused
// launch record itself, because Windows starts that handler in the blocked user's
// own unprivileged session (see blockedCmd in cmd/guard). The cost is that a
// determined local user can append noise, and enough noise eventually rotates
// older entries out. What they cannot do is remove one particular entry, which is
// the property the log exists for, and a rotation leaves a marker of its own - so
// a rotation forced by flooding is visible rather than silent.
//
// A local administrator is outside all of this, exactly as they are everywhere
// else in the guard. The bar here is the bar the rest of the product holds:
// tampering has to be deliberate, and it leaves a mark.
//
// Recording is off until Enable is called. That is not a feature flag - it is
// what keeps `go test ./...` from appending to the real log on a machine where
// the guard is installed. Only the binaries that should write call Enable.
//
// Creating the log is a separate call, Provision, and only privileged code makes
// it. The reason is ownership: ProgramData lets ordinary users create
// subdirectories, so an unprivileged process that created the log would *own* it,
// and an owner holds WRITE_DAC however the DACL reads - it could hand itself
// write access back whenever it liked. So Enable turns recording on and creates
// nothing, appendLine never creates, and the store is brought into being by the
// service and by the two commands that establish protection.
package activity

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Event is one line of the log. Kind is the stable machine-readable identifier;
// Target is what the event was about (a site, an executable, a block id) and
// Detail is a human note Describe does not try to generate. Actor says which
// process recorded it, because "the service closed Steam" and "someone at the
// keyboard unblocked Steam" are different facts about the same rule.
//
// Every field is small and flat on purpose: a line has to be cheap to append and
// cheap to skip past when it cannot be parsed.
type Event struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
	Actor  string    `json:"actor,omitempty"`
}

// The event kinds. These strings are written to disk, so they are API: a log
// written by an older build has to keep reading correctly in a newer one, which
// is also why Describe falls back to showing an unrecognized kind rather than
// dropping the entry.
const (
	// Enforcement that fired.
	LaunchBlocked = "launch.blocked" // a launch was refused before the app started
	AppClosed     = "app.closed"     // something already running was closed
	TamperConfig  = "tamper.config"  // the config was edited behind the guard's back
	TamperPolicy  = "tamper.policy"  // enforcement had been changed and was re-applied

	// Protection turned on and off as a whole.
	ProtectionInstalled = "protection.installed"
	ProtectionRemoved   = "protection.removed"
	ProtectionPaused    = "protection.paused"
	ProtectionResumed   = "protection.resumed"
	ServiceStarted      = "service.started"
	ServiceStopped      = "service.stopped"
	// PauseRefused is a pause turned down because a block was locked. Worth its
	// own kind rather than passing in silence: somebody trying to pause during a
	// commitment is exactly the line this record exists to keep.
	PauseRefused = "pause.refused"

	// Rules added and lifted.
	DomainBlocked   = "domain.blocked"
	DomainUnblocked = "domain.unblocked"
	// The allowlist mode, and the sites let through it. Turning it on blocks the
	// whole web and turning it off unblocks it, so both are worth a line of their
	// own rather than being folded in with an ordinary domain; and a site allowed
	// through is the one kind of "add" in this program that weakens protection.
	AllowlistOn       = "allowlist.on"
	AllowlistOff      = "allowlist.off"
	SiteAllowed       = "site.allowed"
	SiteUnallowed     = "site.unallowed"
	AppBlocked        = "app.blocked"
	AppUnblocked      = "app.unblocked"
	ExtensionEnabled  = "extension.enabled"
	ExtensionDisabled = "extension.disabled"
	LimitReached      = "limit.reached" // a block's daily time budget ran out
	UsageReset        = "usage.reset"   // the record of today's usage was unreadable and was started again
	// CategoryBlocked is a built-in category expanded into the config. It is one
	// event rather than the thirty the expansion performs: "blocked social media"
	// is the fact somebody reading this record is looking for, and thirty lines
	// of Discord.exe, Telegram.exe, facebook.com would bury it.
	CategoryBlocked = "category.blocked"
	// HardeningEnabled and HardeningDisabled are a pinned browser setting being
	// turned on and off - private browsing above all. The disabled half is the one
	// worth recording: it hands back the window a locked extension does not run in,
	// so it belongs in the record next to unblocking a site.
	HardeningEnabled  = "hardening.enabled"
	HardeningDisabled = "hardening.disabled"
	BlockCreated      = "block.created"
	BlockRemoved      = "block.removed"
	BlockLocked       = "block.locked"

	// The password, and attempts on it.
	PasswordChanged = "password.changed"
	PasswordFailed  = "password.failed"

	// Housekeeping.
	UpdateApplied = "update.applied"
	LogRotated    = "log.rotated"
)

// The actors. A CLI command or the status window records the signed-in user's
// name instead (see LocalUser), because for anything done at the keyboard *who*
// did it is the point.
const (
	ActorService = "service"
	ActorAgent   = "agent"
)

// Severities group the kinds for display: the status window colours an event by
// what it means rather than by which subsystem produced it.
const (
	// SeverityEnforced is protection doing its job.
	SeverityEnforced = "enforced"
	// SeverityWeakened is protection being reduced - or somebody trying. A failed
	// password belongs here rather than under "enforced": the gate held, but an
	// attempt on it is exactly the line a parent scanning this list is looking for.
	SeverityWeakened = "weakened"
	// SeverityNeutral is everything else.
	SeverityNeutral = "neutral"
)

const (
	logName     = "activity.jsonl"
	rotatedName = "activity.1.jsonl"
	// tailWindow is how much of the end of a file Recent reads. A line is around
	// 120 bytes, so this is a couple of thousand events - far more than any list
	// will show, and bounded so a large log cannot slow the window down.
	tailWindow = 256 << 10
	// throttleCap bounds the dedupe map. Its keys are rules and image names, so it
	// is naturally small; the cap only stops a pathological machine growing it
	// without limit.
	throttleCap = 512
)

var (
	// dir is where the log lives. A var so tests can point it at a temp directory
	// instead of the real ProgramData one.
	dir = defaultDir()

	// maxBytes is the size at which the log rotates. Generous on purpose: rotation
	// is the one way an entry is lost, so the window in which a flood could push
	// out something worth seeing should be wide enough that the flood itself is the
	// more obvious thing in the log. A var so a test can shrink it rather than
	// writing two megabytes to prove rotation works.
	maxBytes int64 = 2 << 20

	// ensureFile creates the log with the permissions the package comment
	// describes. It is reached through a var because the real one stamps a
	// protected DACL, and a test that applied that to its own temp directory would
	// not be able to delete it again afterwards. store_windows_test.go exercises
	// the real one directly.
	ensureFile = ensure

	mu       sync.Mutex
	actor    string
	enabled  bool
	throttle = map[string]time.Time{}
)

// Enable turns recording on for this process and names the actor its events are
// attributed to. It creates nothing: an unprivileged process appends to the log
// the service already provisioned, and if there is none yet its events are
// dropped. See Provision.
func Enable(who string) {
	mu.Lock()
	actor, enabled = who, true
	mu.Unlock()
}

// Provision creates the log and stamps its permissions. Only privileged code may
// call it - the service, which runs as SYSTEM, and the elevated commands that
// install or resume protection. See the package comment for why creation is not
// folded into Enable.
//
// It is idempotent and safe to call on every start: an existing log is opened for
// append, never truncated, and its permissions are re-asserted the same way the
// service re-asserts the browser policy every cycle.
func Provision() error { return ensureFile(dir, Path()) }

// Path is the log file's full path. Exported so the window and the CLI can tell
// the user where the record lives rather than describing it vaguely.
func Path() string { return filepath.Join(dir, logName) }

// Record appends one event. It is a no-op until Enable has been called, and it
// never reports failure: an unwritable log must not turn into a failed block, and
// there is nowhere useful to report to from inside a sweep that runs every second.
func Record(ev Event) {
	mu.Lock()
	defer mu.Unlock()
	if !enabled {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if ev.Actor == "" {
		ev.Actor = actor
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	appendLine(append(line, '\n'))
}

// RecordThrottled appends an event unless one with the same key was recorded less
// than every ago.
//
// The app sweep is why this exists. It runs about once a second, so an
// application that relaunches itself - or one the guard cannot close, which it
// will keep trying - would otherwise write the same line sixty times a minute and
// bury everything else. The key is the caller's choice of identity for "the same
// event again".
func RecordThrottled(key string, every time.Duration, ev Event) {
	now := ev.Time
	if now.IsZero() {
		now = time.Now()
	}
	mu.Lock()
	if last, seen := throttle[key]; seen && now.Sub(last) < every {
		mu.Unlock()
		return
	}
	if len(throttle) >= throttleCap {
		throttle = map[string]time.Time{}
	}
	throttle[key] = now
	mu.Unlock()
	Record(ev)
}

// Recent returns up to n events, newest first. It reads - it needs neither Enable
// nor any privileges, so the status window calls it directly.
//
// Unparseable lines are skipped rather than treated as an error. Users may append
// to this file (see the package comment), so junk in it is a thing that happens
// and must not take the list out.
func Recent(n int) []Event {
	if n <= 0 {
		return nil
	}
	events := parse(readTail(Path(), tailWindow))
	if len(events) < n {
		// Reach back into the rotated file rather than showing a short list right
		// after a rotation.
		events = append(parse(readTail(filepath.Join(dir, rotatedName), tailWindow)), events...)
	}
	out := make([]Event, 0, min(n, len(events)))
	for i := len(events) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, events[i])
	}
	return out
}

// Describe renders an event as a sentence. It lives here, next to the kinds, so
// the status window and `guard activity` describe an event identically - the same
// reason policy renders a block's schedule summary rather than leaving it to each
// caller.
//
// Detail is deliberately not folded in: callers show it as a second line, and an
// event whose kind says everything has none.
func Describe(e Event) string {
	switch e.Kind {
	case LaunchBlocked:
		return "Blocked a launch of " + or(e.Target, "an application")
	case AppClosed:
		return "Closed " + or(e.Target, "a blocked application")
	case TamperConfig:
		return "Settings were changed outside the app; restored what is enforced"
	case TamperPolicy:
		return "Re-applied protection that had been changed"
	case ProtectionInstalled:
		return "Protection installed"
	case ProtectionRemoved:
		return "Protection uninstalled"
	case ProtectionPaused:
		return "Protection paused"
	case ProtectionResumed:
		return "Protection resumed"
	case PauseRefused:
		return "A pause was refused because a block is locked"
	case ServiceStarted:
		return "The guard started"
	case ServiceStopped:
		return "The guard stopped"
	case DomainBlocked:
		return "Blocked " + or(e.Target, "a site")
	case DomainUnblocked:
		return "Stopped blocking " + or(e.Target, "a site")
	case AllowlistOn:
		return "Blocked every site except the allowlist"
	case AllowlistOff:
		return "Stopped blocking every site"
	case SiteAllowed:
		return "Allowed " + or(e.Target, "a site") + " through"
	case SiteUnallowed:
		return "Stopped allowing " + or(e.Target, "a site") + " through"
	case AppBlocked:
		return "Blocked " + or(e.Target, "an application")
	case AppUnblocked:
		return "Stopped blocking " + or(e.Target, "an application")
	case ExtensionEnabled:
		return "Started protecting " + or(e.Target, "an extension")
	case ExtensionDisabled:
		return "Stopped protecting " + or(e.Target, "an extension")
	case CategoryBlocked:
		return "Blocked the " + or(e.Target, "") + " category"
	case HardeningEnabled:
		return "Pinned the browser setting " + or(e.Target, "")
	case HardeningDisabled:
		return "Stopped pinning the browser setting " + or(e.Target, "")
	case BlockCreated:
		return "Created the scheduled block " + or(e.Target, "")
	case BlockRemoved:
		return "Removed the scheduled block " + or(e.Target, "")
	case BlockLocked:
		return "Locked the scheduled block " + or(e.Target, "")
	case LimitReached:
		return "Daily time limit reached for " + or(e.Target, "a block")
	case UsageReset:
		return "Today's record of time used was unreadable and was started again"
	case PasswordChanged:
		return "The uninstall password was changed"
	case PasswordFailed:
		if e.Target != "" {
			return "Wrong password entered for " + e.Target
		}
		return "Wrong password entered"
	case UpdateApplied:
		return "Updated to " + or(e.Target, "a new version")
	case LogRotated:
		return "Older activity was moved out of this log"
	}
	// A log written by a newer build. Showing the raw kind is worse than a
	// sentence and much better than hiding the entry.
	return e.Kind
}

// Severity groups an event for display. See the Severity* constants.
func (e Event) Severity() string {
	switch e.Kind {
	case LaunchBlocked, AppClosed, TamperConfig, TamperPolicy,
		DomainBlocked, AppBlocked, ExtensionEnabled, BlockCreated, BlockLocked,
		CategoryBlocked, HardeningEnabled, AllowlistOn, SiteUnallowed,
		LimitReached, ProtectionInstalled, ProtectionResumed:
		return SeverityEnforced
	case DomainUnblocked, AppUnblocked, ExtensionDisabled, BlockRemoved, HardeningDisabled,
		AllowlistOff, SiteAllowed,
		ProtectionPaused, ProtectionRemoved, PasswordFailed, UsageReset, PauseRefused:
		return SeverityWeakened
	}
	return SeverityNeutral
}

// LocalUser is the signed-in account's short name, used as the actor for events
// recorded by a CLI command or the status window. A domain-qualified name is
// reduced to the account, because the domain is the same on every line and the
// account is the part that identifies who acted.
func LocalUser() string {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	if name == "" {
		name = os.Getenv("USERNAME")
	}
	if name == "" {
		name = os.Getenv("USER")
	}
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		return "someone at the keyboard"
	}
	return name
}

// appendLine writes one line to the end of the log. Callers hold mu.
//
// It deliberately does not pass O_CREATE. Creating the file is how it gets its
// permissions, and only ensure does that; an unprivileged writer that created the
// file here would leave it with whatever DACL it inherited, which is how an
// append-only log quietly becomes a writable one. No file yet means the event is
// dropped, and the next privileged start creates it.
func appendLine(b []byte) {
	p := Path()
	rotateIfFull(p)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(b)
}

// rotateIfFull moves the log aside once it passes maxBytes and starts a fresh
// one, leaving a marker in the new file so the break is visible. Callers hold mu.
//
// A caller that may not rename in the log directory - an unprivileged appender -
// simply fails here and keeps appending; the next privileged write rotates. That
// is the right way round: growing past the cap is a far smaller problem than an
// unprivileged process being able to move the record aside.
func rotateIfFull(p string) {
	st, err := os.Stat(p)
	if err != nil || st.Size() < maxBytes {
		return
	}
	if err := os.Rename(p, filepath.Join(dir, rotatedName)); err != nil {
		return
	}
	if err := ensureFile(dir, p); err != nil {
		return
	}
	line, err := json.Marshal(Event{
		Time:   time.Now(),
		Kind:   LogRotated,
		Actor:  actor,
		Detail: "the entries before this point moved to " + rotatedName,
	})
	if err != nil {
		return
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// readTail returns the last max bytes of a file, starting at a line boundary. A
// missing or unreadable file reads as empty rather than as an error: the log not
// existing yet is the normal state before the first install.
func readTail(p string, max int64) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	var off int64
	if st.Size() > max {
		off = st.Size() - max
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	if off > 0 {
		// The seek landed inside a line; drop the fragment so it is not parsed as
		// junk - or worse, parsed successfully into a wrong event.
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		} else {
			b = nil
		}
	}
	return b
}

// parse turns log bytes into events in file order, skipping anything that does
// not decode into a usable event.
func parse(b []byte) []Event {
	var out []Event
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if ev.Kind == "" || ev.Time.IsZero() {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// or is s, or fallback when s is blank - so a truncated event still reads as a
// sentence instead of trailing off.
func or(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
