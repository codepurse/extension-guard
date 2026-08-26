package activity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// plainCreate is the stand-in for the real ensure. The real one stamps a
// protected DACL, and a test that applied that to its own temp directory could
// not delete it again afterwards - store_windows_test.go exercises the real one
// on a directory it cleans up by hand.
func plainCreate(d, p string) error {
	if err := os.MkdirAll(d, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

// useTempLog points the package at a fresh log directory, provisions it, turns
// recording on, and restores every piece of package state afterwards. Enable and
// Provision are separate in production too - only privileged code creates the
// store - so calling both here mirrors what the service does at startup.
func useTempLog(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	restore(t)
	dir = tmp
	ensureFile = plainCreate
	Enable("test")
	if err := Provision(); err != nil {
		t.Fatalf("provision the temp log: %v", err)
	}
	return tmp
}

// restore puts the package-level state back the way the test found it.
func restore(t *testing.T) {
	t.Helper()
	oldDir, oldEnsure, oldMax := dir, ensureFile, maxBytes
	oldActor, oldEnabled := actor, enabled
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		dir, ensureFile, maxBytes = oldDir, oldEnsure, oldMax
		actor, enabled = oldActor, oldEnabled
		throttle = map[string]time.Time{}
	})
}

// at is a fixed base time, so an ordering assertion never depends on the clock.
var at = time.Date(2026, 3, 1, 21, 4, 0, 0, time.UTC)

func TestRecentReturnsNewestFirst(t *testing.T) {
	useTempLog(t)

	Record(Event{Time: at, Kind: DomainBlocked, Target: "reddit.com"})
	Record(Event{Time: at.Add(time.Minute), Kind: LaunchBlocked, Target: "steam.exe"})
	Record(Event{Time: at.Add(2 * time.Minute), Kind: ProtectionPaused})

	got := Recent(10)
	if len(got) != 3 {
		t.Fatalf("recorded 3 events, Recent returned %d", len(got))
	}
	want := []string{ProtectionPaused, LaunchBlocked, DomainBlocked}
	for i, kind := range want {
		if got[i].Kind != kind {
			t.Errorf("event %d is %q, want %q (Recent must read newest first)", i, got[i].Kind, kind)
		}
	}
}

func TestRecentStopsAtTheLimit(t *testing.T) {
	useTempLog(t)
	for i := 0; i < 10; i++ {
		Record(Event{Time: at.Add(time.Duration(i) * time.Minute), Kind: AppClosed, Target: "steam.exe"})
	}
	if got := Recent(3); len(got) != 3 {
		t.Fatalf("Recent(3) returned %d events", len(got))
	}
	if got := Recent(0); got != nil {
		t.Errorf("Recent(0) returned %d events, want none", len(got))
	}
}

func TestRecordFillsInTheTimeAndActor(t *testing.T) {
	useTempLog(t)
	Record(Event{Kind: DomainBlocked, Target: "reddit.com"})

	got := Recent(1)
	if len(got) != 1 {
		t.Fatalf("Recent returned %d events, want 1", len(got))
	}
	if got[0].Time.IsZero() {
		t.Error("an event recorded without a time was stored with a zero time")
	}
	if got[0].Actor != "test" {
		t.Errorf("actor is %q, want the one Enable named", got[0].Actor)
	}
}

// Recording stays off until Enable is called. This is what keeps `go test ./...`
// from appending to the real log on a machine where the guard is installed, so it
// is asserted against a log file that already exists and is writable.
func TestRecordDoesNothingBeforeEnable(t *testing.T) {
	tmp := t.TempDir()
	restore(t)
	dir = tmp
	ensureFile = plainCreate
	mu.Lock()
	enabled = false
	mu.Unlock()

	if err := plainCreate(tmp, filepath.Join(tmp, logName)); err != nil {
		t.Fatal(err)
	}
	Record(Event{Kind: DomainBlocked, Target: "reddit.com"})
	RecordThrottled("k", time.Minute, Event{Kind: AppClosed, Target: "steam.exe"})

	if got := Recent(10); len(got) != 0 {
		t.Fatalf("recorded %d events with the log disabled, want none", len(got))
	}
}

// Neither Enable nor Record may create the log - only Provision, which is called
// from privileged code. This is the security property, not a detail: ProgramData
// lets ordinary users create subdirectories, so a log created by an unprivileged
// process would be *owned* by it, and an owner holds WRITE_DAC however the DACL
// reads. That turns an append-only record into a rewritable one.
func TestOnlyProvisionCreatesTheLog(t *testing.T) {
	tmp := t.TempDir()
	restore(t)
	dir = tmp
	// Stand in for an unprivileged caller: the real ensure fails the same way when
	// the directory withholds the right to add a file.
	ensureFile = func(string, string) error { return errors.New("not privileged") }
	Enable("test")

	if _, err := os.Stat(filepath.Join(tmp, logName)); !os.IsNotExist(err) {
		t.Fatalf("Enable created the log (stat error %v); it must only turn recording on", err)
	}

	Record(Event{Kind: LaunchBlocked, Target: "steam.exe"})
	RecordThrottled("k", time.Minute, Event{Kind: AppClosed, Target: "steam.exe"})

	if _, err := os.Stat(filepath.Join(tmp, logName)); !os.IsNotExist(err) {
		t.Fatalf("the log exists after an unprivileged write (stat error %v); its permissions would be wrong", err)
	}
	if got := Recent(10); len(got) != 0 {
		t.Errorf("Recent returned %d events from a log that was never created", len(got))
	}
}

// Provision runs on every service start, so it has to be safe to repeat: an
// existing record must be reopened, never truncated.
func TestProvisionKeepsAnExistingRecord(t *testing.T) {
	useTempLog(t)
	Record(Event{Time: at, Kind: DomainBlocked, Target: "reddit.com"})

	if err := Provision(); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if got := Recent(10); len(got) != 1 {
		t.Fatalf("Recent returned %d events after re-provisioning, want the one recorded", len(got))
	}
}

// Users may append to this file, so junk in it is a thing that happens. It must
// cost the surrounding entries nothing.
func TestRecentSkipsUnparseableLines(t *testing.T) {
	tmp := useTempLog(t)
	Record(Event{Time: at, Kind: DomainBlocked, Target: "reddit.com"})

	f, err := os.OpenFile(filepath.Join(tmp, logName), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Not JSON; JSON but not an event; an event with no kind; and a blank line.
	if _, err := f.WriteString("garbage\n{\"hello\":1}\n{\"time\":\"2026-03-01T21:04:00Z\"}\n\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	Record(Event{Time: at.Add(time.Minute), Kind: ProtectionPaused})

	got := Recent(10)
	if len(got) != 2 {
		t.Fatalf("Recent returned %d events, want the 2 real ones", len(got))
	}
	if got[0].Kind != ProtectionPaused || got[1].Kind != DomainBlocked {
		t.Errorf("got %q then %q, want %q then %q", got[0].Kind, got[1].Kind, ProtectionPaused, DomainBlocked)
	}
}

func TestRecentReachesIntoTheRotatedFile(t *testing.T) {
	tmp := useTempLog(t)

	older := Event{Time: at, Kind: DomainBlocked, Target: "reddit.com"}
	line, err := json.Marshal(older)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, rotatedName), append(line, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	Record(Event{Time: at.Add(time.Hour), Kind: ProtectionPaused})

	got := Recent(10)
	if len(got) != 2 {
		t.Fatalf("Recent returned %d events, want the current one and the rotated one", len(got))
	}
	if got[0].Kind != ProtectionPaused {
		t.Errorf("newest event is %q, want %q", got[0].Kind, ProtectionPaused)
	}
	if got[1].Kind != DomainBlocked {
		t.Errorf("oldest event is %q, want the one from the rotated file", got[1].Kind)
	}
}

// A full log is moved aside, a fresh one started, and the break is marked - so a
// rotation forced by flooding the log is visible rather than silent.
func TestRotationMovesTheLogAsideAndMarksTheBreak(t *testing.T) {
	tmp := useTempLog(t)
	maxBytes = 400

	for i := 0; i < 12; i++ {
		Record(Event{Time: at.Add(time.Duration(i) * time.Minute), Kind: AppClosed, Target: "steam.exe"})
	}

	if _, err := os.Stat(filepath.Join(tmp, rotatedName)); err != nil {
		t.Fatalf("the log passed its cap but was not rotated: %v", err)
	}
	st, err := os.Stat(filepath.Join(tmp, logName))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() >= 400 {
		t.Errorf("the current log is %d bytes; rotation did not start a fresh one", st.Size())
	}

	var marked bool
	for _, ev := range Recent(50) {
		if ev.Kind == LogRotated {
			marked = true
			if !strings.Contains(ev.Detail, rotatedName) {
				t.Errorf("the rotation marker does not say where the entries went: %q", ev.Detail)
			}
		}
	}
	if !marked {
		t.Error("rotation left no marker, so the gap in the record is silent")
	}
	// Retention is bounded to the current file plus one previous - that is the
	// cost of rotation, and it is the reason maxBytes is set high in production.
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("log directory holds %v, want just the current and rotated files", names)
	}
	// What survives is still readable across both files, and the last thing
	// recorded is still there - a rotation must not swallow the newest entry.
	got := Recent(50)
	if len(got) < 2 {
		t.Fatalf("Recent returned %d events after rotation, want the surviving tail", len(got))
	}
	last := at.Add(11 * time.Minute)
	var found bool
	for _, ev := range got {
		if ev.Kind == AppClosed && ev.Time.Equal(last) {
			found = true
		}
	}
	if !found {
		t.Error("the most recent event is missing after rotation")
	}
}

func TestReadTailStartsAtALineBoundary(t *testing.T) {
	tmp := useTempLog(t)
	for i := 0; i < 6; i++ {
		Record(Event{Time: at.Add(time.Duration(i) * time.Minute), Kind: AppClosed, Target: "steam.exe"})
	}
	p := filepath.Join(tmp, logName)
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}

	// A window that is certain to land inside a line rather than on a boundary.
	b := readTail(p, st.Size()/2+7)
	if len(b) == 0 {
		t.Fatal("readTail returned nothing")
	}
	if !json.Valid(firstLine(b)) {
		t.Fatalf("readTail returned a partial first line: %q", firstLine(b))
	}
	events := parse(b)
	if len(events) == 0 {
		t.Fatal("no events parsed out of the tail")
	}
	for _, ev := range events {
		if ev.Kind != AppClosed {
			t.Fatalf("parsed a damaged event: %+v", ev)
		}
	}
}

func firstLine(b []byte) []byte {
	if i := strings.IndexByte(string(b), '\n'); i >= 0 {
		return b[:i]
	}
	return b
}

// The sweep runs about once a second, so a repeated event has to collapse or it
// buries everything else in the log.
func TestRecordThrottledCollapsesRepeats(t *testing.T) {
	useTempLog(t)
	const window = 5 * time.Minute
	closed := func(target string, offset time.Duration) Event {
		return Event{Time: at.Add(offset), Kind: AppClosed, Target: target}
	}

	RecordThrottled("steam.exe", window, closed("steam.exe", 0))
	RecordThrottled("steam.exe", window, closed("steam.exe", time.Minute))
	RecordThrottled("steam.exe", window, closed("steam.exe", 2*time.Minute))
	// Past the window: recorded again.
	RecordThrottled("steam.exe", window, closed("steam.exe", 6*time.Minute))
	// A different key is a different event, however recently the first one fired.
	RecordThrottled("other.exe", window, closed("other.exe", 6*time.Minute))

	got := Recent(50)
	if len(got) != 3 {
		t.Fatalf("throttled 5 calls into %d events, want 3", len(got))
	}
	if got[0].Target != "other.exe" {
		t.Errorf("newest event is for %q, want other.exe", got[0].Target)
	}
}

// Every kind needs a sentence. A kind added without one falls through to the
// default and shows the raw identifier in the window, which this catches.
func TestDescribeHasASentenceForEveryKind(t *testing.T) {
	kinds := []string{
		LaunchBlocked, AppClosed, TamperConfig, TamperPolicy,
		ProtectionInstalled, ProtectionRemoved, ProtectionPaused, ProtectionResumed,
		ServiceStarted, ServiceStopped, PauseRefused,
		DomainBlocked, DomainUnblocked, AppBlocked, AppUnblocked,
		ExtensionEnabled, ExtensionDisabled, LimitReached, UsageReset,
		BlockCreated, BlockRemoved, BlockLocked,
		PasswordChanged, PasswordFailed, UpdateApplied, LogRotated,
	}
	for _, kind := range kinds {
		got := Describe(Event{Time: at, Kind: kind, Target: "steam.exe"})
		if strings.TrimSpace(got) == "" {
			t.Errorf("%s: Describe returned nothing", kind)
		}
		if got == kind {
			t.Errorf("%s: Describe fell through to the raw kind; give it a sentence", kind)
		}
	}
}

// An event a newer build wrote must still show up, even unrecognized.
func TestDescribeKeepsAnUnknownKindVisible(t *testing.T) {
	if got := Describe(Event{Time: at, Kind: "quota.exceeded"}); got != "quota.exceeded" {
		t.Errorf("Describe of an unknown kind returned %q, want the kind itself", got)
	}
}

// A missing target must not leave a sentence trailing off mid-phrase.
func TestDescribeReadsAsASentenceWithoutATarget(t *testing.T) {
	for _, kind := range []string{LaunchBlocked, DomainBlocked, ExtensionDisabled, UpdateApplied} {
		got := Describe(Event{Time: at, Kind: kind})
		if strings.HasSuffix(got, " ") || strings.HasSuffix(got, "of") || strings.HasSuffix(got, "blocking") {
			t.Errorf("%s: %q trails off when the target is missing", kind, got)
		}
	}
}

func TestSeveritySeparatesWeakeningFromEnforcing(t *testing.T) {
	cases := map[string]string{
		LaunchBlocked:     SeverityEnforced,
		AppClosed:         SeverityEnforced,
		TamperConfig:      SeverityEnforced,
		DomainBlocked:     SeverityEnforced,
		DomainUnblocked:   SeverityWeakened,
		ExtensionDisabled: SeverityWeakened,
		ProtectionPaused:  SeverityWeakened,
		PasswordFailed:    SeverityWeakened,
		ServiceStarted:    SeverityNeutral,
		UpdateApplied:     SeverityNeutral,
		LogRotated:        SeverityNeutral,
	}
	for kind, want := range cases {
		if got := (Event{Kind: kind}).Severity(); got != want {
			t.Errorf("%s: severity %q, want %q", kind, got, want)
		}
	}
}

func TestLocalUserIsNeverBlank(t *testing.T) {
	if strings.TrimSpace(LocalUser()) == "" {
		t.Error("LocalUser returned nothing; an event would be attributed to nobody")
	}
}
