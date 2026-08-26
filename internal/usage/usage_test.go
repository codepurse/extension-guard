package usage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// tempStore points the package at a directory the test owns, and swaps the two
// permission-stamping hooks for ones that do nothing. The real ones apply a
// protected DACL that takes ownership, which a test directory would not survive
// being cleaned up afterwards - store_windows_test.go exercises those directly.
func tempStore(t *testing.T) string {
	t.Helper()
	prevDir, prevEnsure, prevSecure := dir, ensureFile, secureFile
	t.Cleanup(func() { dir, ensureFile, secureFile = prevDir, prevEnsure, prevSecure })

	dir = t.TempDir()
	// Everything the real ensure does except stamp permissions, so that a test of
	// "Provision does not truncate" is testing something.
	ensureFile = func(d, p string) error {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		return f.Close()
	}
	secureFile = func(string) error { return nil }
	return dir
}

// tick advances the tracker one second at a time, the way the service does, and
// returns the moment it stopped at. Tests use it rather than jumping straight to
// "half an hour later" because a single observation is capped at maxCharge - which
// is the point of the cap, and testing around it would be testing something the
// service never does.
func tick(tr *Tracker, start time.Time, d string, day string, ids ...string) time.Time {
	span, err := time.ParseDuration(d)
	if err != nil {
		panic(err)
	}
	now := start
	for elapsed := time.Duration(0); elapsed < span; elapsed += time.Second {
		now = start.Add(elapsed + time.Second)
		tr.Observe(now, day, ids)
	}
	return now
}

// A day apart from the next: the ledger files counters per day, and every test
// below needs at least two to say anything interesting.
const (
	day1 = "2026-08-20"
	day2 = "2026-08-21"
)

func TestObserveChargesElapsedTime(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)

	// The first observation establishes the baseline and charges nothing: there is
	// no earlier moment to have been running since.
	if got := tr.Observe(start, day1, []string{"games"}); got != 0 {
		t.Errorf("first observation charged %s, want 0", got)
	}
	for i := 1; i <= 60; i++ {
		tr.Observe(start.Add(time.Duration(i)*time.Second), day1, []string{"games"})
	}
	if got := tr.Spent(day1)["games"]; got != time.Minute {
		t.Errorf("after 60 one-second ticks: %s, want 1m", got)
	}
}

func TestObserveOnlyChargesBlocksGiven(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{"games", "chat"})
	tick(tr, start, "30s", day1, "games")

	spent := tr.Spent(day1)
	if spent["games"] != 30*time.Second {
		t.Errorf("games: %s, want 30s", spent["games"])
	}
	// "chat" was named on the baseline observation, which charges nothing, and not
	// on the one that did charge - so it must still be at zero.
	if spent["chat"] != 0 {
		t.Errorf("chat: %s, want 0 (it was not running for the charged interval)", spent["chat"])
	}
}

// A ticker on a busy machine delivers 1.2s then 0.8s, not 1.0s twice. Truncating
// each interval on its own would charge one second for every two, which is a
// discount rather than a rounding error - so the remainder has to be carried.
func TestObserveCarriesSubSecondRemainders(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)

	// Thirty observations 1.5s apart: forty-five seconds of use, however it is
	// chopped up.
	now := start
	tr.Observe(now, day1, []string{"games"})
	for i := 0; i < 30; i++ {
		now = now.Add(1500 * time.Millisecond)
		tr.Observe(now, day1, []string{"games"})
	}
	if got := tr.Spent(day1)["games"]; got != 45*time.Second {
		t.Errorf("thirty 1.5s intervals charged %s, want 45s", got)
	}

	// And the remainder is dropped when nothing is running, rather than being paid
	// out to whatever runs next.
	now = now.Add(500 * time.Millisecond)
	tr.Observe(now, day1, []string{"games"})
	now = now.Add(500 * time.Millisecond)
	tr.Observe(now, day1, nil)
	now = now.Add(500 * time.Millisecond)
	tr.Observe(now, day1, []string{"games"})
	if got := tr.Spent(day1)["games"]; got != 45*time.Second {
		t.Errorf("after an idle interval: %s, want the same 45s", got)
	}
}

// A gap far larger than the tick interval is the machine having been asleep, and
// an app that was not usable must not be charged for the night.
func TestObserveCapsALongGap(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{"games"})
	tr.Observe(start.Add(8*time.Hour), day1, []string{"games"})

	if got := tr.Spent(day1)["games"]; got != maxCharge {
		t.Errorf("an eight-hour gap charged %s, want the %s cap", got, maxCharge)
	}
}

// Winding the clock back must not charge a negative interval, and must not leave
// the baseline in the future either - the next observation after the rollback
// should charge what actually passed from the rollback point.
func TestObserveIgnoresTimeMovingBackwards(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{"games"})
	tr.Observe(start.Add(10*time.Second), day1, []string{"games"})
	tr.Observe(start.Add(-time.Hour), day1, []string{"games"}) // clock moved back

	if got := tr.Spent(day1)["games"]; got != 10*time.Second {
		t.Errorf("after a rollback: %s, want the 10s charged before it", got)
	}
	tr.Observe(start.Add(5*time.Second), day1, []string{"games"})
	if got := tr.Spent(day1)["games"]; got < 10*time.Second {
		t.Errorf("spent time went backwards: %s", got)
	}
}

// The whole reason the ledger is on disk: a service restart in the middle of the
// day must not hand back the budget already spent.
func TestCountersSurviveARestart(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{"games"})
	tick(tr, start, "5m", day1, "games")
	if err := tr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	restarted := NewTracker()
	if got := restarted.Spent(day1)["games"]; got != 5*time.Minute {
		t.Errorf("after a restart: %s, want 5m", got)
	}
	if state := restarted.State(); state != StateOK {
		t.Errorf("state after a restart: %s, want ok", state)
	}
}

// Rolling the date back to a day with budget left is the obvious way to get a
// limit back. The ledger refuses to serve a day earlier than the latest it has
// recorded, so the counter that comes back is today's.
func TestRolledBackDateStillReadsTodaysCounter(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 21, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day2, []string{"games"})
	now := tick(tr, start, "45m", day2, "games")

	if got := tr.Spent(day1)["games"]; got != 45*time.Minute {
		t.Errorf("asking for yesterday returned %s, want today's 45m", got)
	}
	// And charging into the earlier day lands on the later one, so time cannot be
	// moved off the day it was spent on.
	tick(tr, now, "10s", day1, "games")
	if got := tr.Spent(day2)["games"]; got <= 45*time.Minute {
		t.Errorf("today's counter did not advance: %s", got)
	}
}

func TestNewDayStartsFresh(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{"games"})
	tick(tr, start, "45m", day1, "games")

	if got := tr.Spent(day2)["games"]; got != 0 {
		t.Errorf("the next day starts at %s, want 0", got)
	}
}

func TestFlushIsANoOpWithNothingToWrite(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	if err := tr.Flush(); err != nil {
		t.Fatalf("Flush with nothing recorded: %v", err)
	}
	if _, err := os.Stat(Path()); !os.IsNotExist(err) {
		t.Error("an empty flush wrote a file")
	}
}

func TestMissingLedgerIsFreshNotBroken(t *testing.T) {
	tempStore(t)
	led, state := Load()
	if state != StateFresh {
		t.Errorf("state: %s, want fresh", state)
	}
	if got := led.Spent(day1)["games"]; got != 0 {
		t.Errorf("spent: %s, want 0", got)
	}
}

// A ledger that exists and cannot be parsed is the fail-closed case: the caller
// has to be able to tell it apart from a fresh one, because policy turns the
// difference into "every limit is spent" rather than "nothing is spent".
func TestUnreadableLedgerIsReportedAsSuch(t *testing.T) {
	d := tempStore(t)
	if err := os.WriteFile(filepath.Join(d, fileName), []byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, state := Load(); state != StateUnreadable {
		t.Errorf("state: %s, want unreadable", state)
	}
	// An empty file is the other half of that distinction: a torn write of ours has
	// no number in it to protect, so it reads as fresh.
	if err := os.WriteFile(filepath.Join(d, fileName), []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, state := Load(); state != StateFresh {
		t.Errorf("empty file: %s, want fresh", state)
	}
}

// The trap this avoids: while a ledger reads as unreadable every limit counts as
// spent, so the app it covers is blocked - and a blocked app cannot run, so nothing
// is charged and nothing would ever be flushed. The tracker has to be willing to
// rewrite the file with nothing recorded at all.
func TestAnUnreadableLedgerIsRebuiltWithoutBeingUsed(t *testing.T) {
	d := tempStore(t)
	if err := os.WriteFile(filepath.Join(d, fileName), []byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker()
	if tr.State() != StateUnreadable {
		t.Fatalf("state: %s, want unreadable", tr.State())
	}
	// No Observe call at all: this is the case where the app is blocked and cannot
	// generate any usage to flush.
	if err := tr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if tr.State() != StateOK {
		t.Errorf("state after the rebuild: %s, want ok", tr.State())
	}
	if _, state := Load(); state != StateOK {
		t.Error("the file on disk still does not parse")
	}
}

func TestFlushClearsAnUnreadableState(t *testing.T) {
	d := tempStore(t)
	if err := os.WriteFile(filepath.Join(d, fileName), []byte("rubbish"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker()
	if tr.State() != StateUnreadable {
		t.Fatalf("state: %s, want unreadable", tr.State())
	}
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{"games"})
	tick(tr, start, "1m", day1, "games")
	if err := tr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if tr.State() != StateOK {
		t.Errorf("state after a flush: %s, want ok - the file is ours now", tr.State())
	}
	if _, state := Load(); state != StateOK {
		t.Error("the file on disk still does not parse after a flush")
	}
}

// A rewrite must replace the file rather than land next to it, and it must not
// leave the staging file behind.
func TestFlushLeavesNoTempFile(t *testing.T) {
	d := tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{"games"})
	tick(tr, start, "1m", day1, "games")
	if err := tr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d, tempName)); !os.IsNotExist(err) {
		t.Error("the staging file is still there")
	}
}

// A pre-existing file at the staging path is the one hostile case writeTemp exists
// for: until the guard is installed, the directory it sits in may let an ordinary
// user create files there.
func TestFlushOverwritesAStaleTempFile(t *testing.T) {
	d := tempStore(t)
	if err := os.WriteFile(filepath.Join(d, tempName), []byte("in the way"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{"games"})
	tick(tr, start, "1m", day1, "games")
	if err := tr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := mustLoad(t).Spent(day1)["games"]; got != time.Minute {
		t.Errorf("spent: %s, want 1m", got)
	}
}

func TestPruneKeepsTheMostRecentDays(t *testing.T) {
	tempStore(t)
	led := Ledger{}
	for i := 1; i <= keepDays+10; i++ {
		day := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, i).Format("2006-01-02")
		led.add(day, "games", 60)
	}
	newest := led.LastDay
	if err := led.save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	saved := mustLoad(t)
	if len(saved.Days) != keepDays {
		t.Errorf("kept %d days, want %d", len(saved.Days), keepDays)
	}
	if _, ok := saved.Days[newest]; !ok {
		t.Errorf("the most recent day (%s) was pruned", newest)
	}
	if saved.LastDay != newest {
		t.Errorf("LastDay is %q, want %q", saved.LastDay, newest)
	}
}

// The ledger is read by people as well as by the guard: it is the file the status
// window points at when someone asks where the number came from.
func TestLedgerIsPlainReadableJSON(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{"games"})
	tick(tr, start, "90s", day1, "games")
	if err := tr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	data, err := os.ReadFile(Path())
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Days    map[string]map[string]int `json:"days"`
		LastDay string                    `json:"lastDay"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("the ledger does not parse as the documented shape: %v", err)
	}
	if decoded.Days[day1]["games"] != 90 {
		t.Errorf("seconds recorded: %d, want 90", decoded.Days[day1]["games"])
	}
	if decoded.LastDay != day1 {
		t.Errorf("lastDay: %q, want %q", decoded.LastDay, day1)
	}
}

func TestKeyNormalizesBlockIDs(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{" Games "})
	tick(tr, start, "1m", day1, "GAMES")

	// One block, however it was spelled. A counter filed under a spelling nothing
	// looks up is a limit that never fires.
	spent := tr.Spent(day1)
	if len(spent) != 1 {
		t.Fatalf("spent has %d entries, want 1: %v", len(spent), spent)
	}
	if got := spent[Key("games")]; got != time.Minute {
		t.Errorf("games: %s, want 1m", got)
	}
}

func TestProvisionIsIdempotentAndDoesNotTruncate(t *testing.T) {
	tempStore(t)
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	tr.Observe(start, day1, []string{"games"})
	tick(tr, start, "1m", day1, "games")
	if err := tr.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := Provision(); err != nil {
			t.Fatalf("Provision: %v", err)
		}
	}
	if got := mustLoad(t).Spent(day1)["games"]; got != time.Minute {
		t.Errorf("Provision cost %s of a recorded minute", time.Minute-got)
	}
}

func mustLoad(t *testing.T) Ledger {
	t.Helper()
	led, state := Load()
	if state != StateOK {
		t.Fatalf("Load: state %s, want ok", state)
	}
	return led
}
