package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/codepurse/extension-guard/internal/usage"
)

// limitedConfig is the shape the feature exists for: an application that is
// blocked, and a block that allows forty-five minutes of it a day.
func limitedConfig() Config {
	return Config{
		Apps: []App{{Kind: AppExe, Value: "steam.exe"}, {Kind: AppExe, Value: "mygame.exe"}},
		Blocks: []Block{{
			ID:    "games",
			Label: "Games",
			Apps:  []string{"steam.exe"},
			Limit: "45m",
		}},
	}
}

// spentOf builds the counters a resolution is done against, saving every test
// below from naming the field.
func spentOf(pairs map[string]time.Duration) Spent {
	by := make(map[string]time.Duration, len(pairs))
	for id, d := range pairs {
		by[usage.Key(id)] = d
	}
	return Spent{ByBlock: by}
}

// stubLedger points the package's ledger read at a fixed answer, so a test can
// exercise the default (non-...With) resolution path without a file on disk.
func stubLedger(t *testing.T, spent map[string]time.Duration, state usage.State) {
	t.Helper()
	prev := spentOn
	t.Cleanup(func() { spentOn = prev })
	spentOn = func(string) (map[string]time.Duration, usage.State) {
		by := make(map[string]time.Duration, len(spent))
		for id, d := range spent {
			by[usage.Key(id)] = d
		}
		return by, state
	}
}

func TestParseLimitAcceptsWhatPeopleType(t *testing.T) {
	cases := map[string]time.Duration{
		"45m":     45 * time.Minute,
		"1h30m":   90 * time.Minute,
		"1.5h":    90 * time.Minute,
		"45":      45 * time.Minute, // a bare number is minutes
		" 90 ":    90 * time.Minute,
		"2H":      2 * time.Hour,
		"24h":     24 * time.Hour, // exactly the maximum
		"30m0.5s": 30 * time.Minute,
	}
	for in, want := range cases {
		got, err := ParseLimit(in)
		if err != nil {
			t.Errorf("ParseLimit(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLimit(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestParseLimitRefusesWhatCannotBeMet(t *testing.T) {
	for _, in := range []string{"", "  ", "0", "0m", "-5m", "25h", "48h", "soon", "45mm"} {
		if got, err := ParseLimit(in); err == nil {
			t.Errorf("ParseLimit(%q) = %s, want an error", in, got)
		}
	}
}

// A budget longer than the day it resets in can never run out, so accepting one
// would mean shipping a limit that looks like protection and is none.
func TestParseLimitRefusesLongerThanADay(t *testing.T) {
	_, err := ParseLimit("25h")
	if err == nil {
		t.Fatal("a 25-hour limit was accepted")
	}
	if !strings.Contains(err.Error(), "never be reached") {
		t.Errorf("the error does not say why: %v", err)
	}
}

func TestExhaustedComparesSpentAgainstTheBudget(t *testing.T) {
	b := Block{ID: "games", Apps: []string{"steam.exe"}, Limit: "45m"}
	cases := []struct {
		spent time.Duration
		want  bool
	}{
		{0, false},
		{44 * time.Minute, false},
		{45*time.Minute - time.Second, false},
		{45 * time.Minute, true}, // reaching the limit spends it
		{2 * time.Hour, true},
	}
	for _, c := range cases {
		sp := spentOf(map[string]time.Duration{"games": c.spent})
		if got := b.Exhausted(sp); got != c.want {
			t.Errorf("Exhausted with %s spent = %v, want %v", c.spent, got, c.want)
		}
	}
}

func TestBlockWithNoLimitIsNeverExhausted(t *testing.T) {
	b := Block{ID: "always"}
	if b.Exhausted(spentOf(map[string]time.Duration{"always": 100 * time.Hour})) {
		t.Error("a block with no limit reported its budget as spent")
	}
	if b.HasLimit() {
		t.Error("HasLimit is true for a block with no limit")
	}
}

// The fail-closed rule. A ledger that exists and cannot be read must not be taken
// for a ledger with nothing in it, or corrupting the file would be the way to
// reset every limit.
func TestUnreadableLedgerSpendsEveryBudget(t *testing.T) {
	b := Block{ID: "games", Apps: []string{"steam.exe"}, Limit: "45m"}
	sp := Spent{Unreadable: true}
	if !b.Exhausted(sp) {
		t.Error("an unreadable ledger left the budget available")
	}
	if got := b.Remaining(sp); got != 0 {
		t.Errorf("Remaining with an unreadable ledger = %s, want 0", got)
	}
}

func TestRemainingNeverGoesNegative(t *testing.T) {
	b := Block{ID: "games", Apps: []string{"steam.exe"}, Limit: "45m"}
	if got := b.Remaining(spentOf(map[string]time.Duration{"games": 10 * time.Minute})); got != 35*time.Minute {
		t.Errorf("Remaining = %s, want 35m", got)
	}
	if got := b.Remaining(spentOf(map[string]time.Duration{"games": 3 * time.Hour})); got != 0 {
		t.Errorf("Remaining after overrunning = %s, want 0", got)
	}
}

// EnforcingAt is where windows and limits compose. Both have to be satisfied: in
// window, and out of budget.
func TestEnforcingAtCombinesWindowAndLimit(t *testing.T) {
	b := Block{
		ID:      "evenings",
		Apps:    []string{"steam.exe"},
		Limit:   "45m",
		Windows: []Window{{Start: "18:00", End: "22:00"}},
	}
	inside, outside := at(20, 19, 0), at(20, 9, 0)
	fresh := spentOf(map[string]time.Duration{"evenings": 0})
	gone := spentOf(map[string]time.Duration{"evenings": time.Hour})

	if b.EnforcingAt(inside, fresh) {
		t.Error("in window with budget left: enforcing, want not")
	}
	if !b.EnforcingAt(inside, gone) {
		t.Error("in window with the budget gone: not enforcing, want enforcing")
	}
	if b.EnforcingAt(outside, gone) {
		t.Error("out of window: enforcing, want not - the block does not apply at that hour")
	}
	// A block with a window and no limit is unchanged by any of this.
	plain := Block{ID: "plain", Windows: b.Windows}
	if !plain.EnforcingAt(inside, fresh) || plain.EnforcingAt(outside, fresh) {
		t.Error("a block without a limit no longer follows its window")
	}
}

// The end-to-end rule: while there is budget the app is released, and the moment
// the budget is gone it is blocked. An app no limited block covers is untouched.
func TestActiveAtWithResolvesALimit(t *testing.T) {
	cfg := limitedConfig()
	now := at(20, 19, 0)

	withBudget := cfg.ActiveAtWith(now, spentOf(map[string]time.Duration{"games": 10 * time.Minute}))
	blocked := withBudget.BlockedApps()
	if len(blocked) != 1 || blocked[0].Value != "mygame.exe" {
		t.Errorf("with budget left: blocked = %+v, want only mygame.exe", blocked)
	}
	// It has to be reported as inactive rather than simply missing, because that is
	// what tells ApplyApps to take the launch block away again.
	if stale := withBudget.InactiveApps(); len(stale) != 1 || stale[0].Value != "steam.exe" {
		t.Errorf("with budget left: inactive = %+v, want steam.exe", stale)
	}

	spent := cfg.ActiveAtWith(now, spentOf(map[string]time.Duration{"games": 45 * time.Minute}))
	if got := len(spent.BlockedApps()); got != 2 {
		t.Errorf("with the budget spent: %d apps blocked, want 2", got)
	}
}

// The service notices a limit running out the same way it notices a window
// opening: the signature changes. Without this, enforcement would wait for the
// 30-second backstop.
func TestActiveSignatureChangesWhenABudgetRunsOut(t *testing.T) {
	cfg := limitedConfig()
	now := at(20, 19, 0)
	before := cfg.ActiveSignatureWith(now, spentOf(map[string]time.Duration{"games": 44 * time.Minute}))
	after := cfg.ActiveSignatureWith(now, spentOf(map[string]time.Duration{"games": 45 * time.Minute}))
	if before == after {
		t.Error("the signature did not change when the budget ran out")
	}
}

// A second block that governs the same app around the clock keeps it blocked
// whatever the limit says: enforced time is the union, so adding a block can only
// ever add enforcement.
func TestAnAlwaysOnBlockOverridesABudget(t *testing.T) {
	cfg := limitedConfig()
	cfg.Blocks = append(cfg.Blocks, Block{ID: "hard", Apps: []string{"steam.exe"}})
	active := cfg.ActiveAtWith(at(20, 19, 0), spentOf(map[string]time.Duration{"games": 0}))
	if got := len(active.BlockedApps()); got != 2 {
		t.Errorf("%d apps blocked, want 2 - the always-on block still covers steam.exe", got)
	}
}

// A limit narrows enforcement, so creating one costs the password. This is the
// fact the CLI and the status window both gate on.
func TestNarrowsCoversALimit(t *testing.T) {
	if !(Block{ID: "games", Limit: "45m"}).Narrows() {
		t.Error("a block with a limit does not report that it narrows enforcement")
	}
	if (Block{ID: "hard"}).Narrows() {
		t.Error("an always-on block reports that it narrows enforcement")
	}
}

// A lock has to cover the limit, or a block locked for a week could have its
// forty-five minutes a day quietly turned into ten hours - as much a release as
// deleting the block.
func TestLockedBlockRefusesARaisedLimit(t *testing.T) {
	now := time.Now()
	locked := limitedConfig()
	locked.Blocks[0].LockedUntil = now.Add(72 * time.Hour).Format(time.RFC3339)

	raised := limitedConfig()
	raised.Blocks[0].LockedUntil = locked.Blocks[0].LockedUntil
	raised.Blocks[0].Limit = "10h"
	if err := CheckLockedBlocks(locked, raised, now); err == nil {
		t.Error("raising a locked block's limit was allowed")
	}

	// Lowering it is refused too, for the same reason every other edit is: the rule
	// is that a locked block is immutable, and deciding which changes are safe is
	// exactly the reasoning this package refuses to do.
	lowered := limitedConfig()
	lowered.Blocks[0].LockedUntil = locked.Blocks[0].LockedUntil
	lowered.Blocks[0].Limit = "10m"
	if err := CheckLockedBlocks(locked, lowered, now); err == nil {
		t.Error("changing a locked block's limit at all was allowed")
	}

	// Rewriting the same length of time differently is not an edit.
	restated := limitedConfig()
	restated.Blocks[0].LockedUntil = locked.Blocks[0].LockedUntil
	restated.Blocks[0].Limit = "0h45m0s"
	if err := CheckLockedBlocks(locked, restated, now); err != nil {
		t.Errorf("restating 45m as 0h45m0s was treated as a change: %v", err)
	}
}

// Adding a limit to a locked block that had none is still an edit to a locked
// block, and it weakens it, so it is refused.
func TestLockedBlockRefusesANewLimit(t *testing.T) {
	now := time.Now()
	current := Config{
		Apps: []App{{Kind: AppExe, Value: "steam.exe"}},
		Blocks: []Block{{
			ID:          "hard",
			Apps:        []string{"steam.exe"},
			LockedUntil: now.Add(72 * time.Hour).Format(time.RFC3339),
		}},
	}
	proposed := current
	proposed.Blocks = []Block{current.Blocks[0]}
	proposed.Blocks[0].Limit = "45m"
	if err := CheckLockedBlocks(current, proposed, now); err == nil {
		t.Error("adding a daily allowance to a locked block was allowed")
	}
}

func TestValidateRefusesALimitOnWhatCannotBeMeasured(t *testing.T) {
	cases := map[string]func(*Config){
		"a limit covering a site": func(c *Config) {
			c.Domains = []Domain{{Name: "reddit.com"}}
			c.Blocks[0].Domains = []string{"reddit.com"}
		},
		"a limit covering an extension": func(c *Config) {
			c.Extensions = []Extension{{Name: "sieve"}}
			c.Blocks[0].Extensions = []string{"sieve"}
		},
		"a limit covering everything": func(c *Config) {
			c.Blocks[0].Apps = nil
		},
		"an unreadable limit": func(c *Config) {
			c.Blocks[0].Limit = "whenever"
		},
		"a limit longer than a day": func(c *Config) {
			c.Blocks[0].Limit = "30h"
		},
	}
	for name, mutate := range cases {
		cfg := limitedConfig()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestValidateAcceptsALimitOnApps(t *testing.T) {
	if err := limitedConfig().Validate(); err != nil {
		t.Errorf("a limit covering an app was refused: %v", err)
	}
	// And with a window as well, which is the "45 minutes during these hours" shape.
	cfg := limitedConfig()
	cfg.Blocks[0].Windows = []Window{{Start: "18:00", End: "22:00"}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("a limit with a window was refused: %v", err)
	}
}

func TestValidateChecksTheResetTime(t *testing.T) {
	cfg := limitedConfig()
	cfg.ResetAt = "4am"
	if err := cfg.Validate(); err == nil {
		t.Error(`resetAt "4am" was accepted`)
	}
	cfg.ResetAt = "04:00"
	if err := cfg.Validate(); err != nil {
		t.Errorf(`resetAt "04:00" was refused: %v`, err)
	}
}

// The day boundary is what makes "a day" mean the user's day rather than the
// calendar's: with a 04:00 reset, half past midnight still belongs to yesterday.
func TestDayKeyFollowsTheResetTime(t *testing.T) {
	cfg := limitedConfig()
	if got := cfg.DayKey(at(20, 0, 30)); got != "2026-08-20" {
		t.Errorf("with no reset configured: %s, want 2026-08-20", got)
	}

	// With the day starting at 04:00, half past midnight still belongs to the day
	// before - which is the whole reason the setting exists.
	cfg.ResetAt = "04:00"
	if got := cfg.DayKey(at(20, 0, 30)); got != "2026-08-19" {
		t.Errorf("00:30 on the 20th: %s, want 2026-08-19", got)
	}
	if got := cfg.DayKey(at(20, 4, 0)); got != "2026-08-20" {
		t.Errorf("04:00 on the 20th: %s, want 2026-08-20", got)
	}
	if got := cfg.DayKey(at(20, 23, 59)); got != "2026-08-20" {
		t.Errorf("23:59 on the 20th: %s, want 2026-08-20", got)
	}
}

// A config with no limits must not read the ledger at all: everything this feature
// costs is behind that check, so an install that never uses it pays nothing.
func TestSpentAtDoesNotReadTheLedgerWithoutLimits(t *testing.T) {
	read := false
	prev := spentOn
	t.Cleanup(func() { spentOn = prev })
	spentOn = func(string) (map[string]time.Duration, usage.State) {
		read = true
		return nil, usage.StateOK
	}

	cfg := Config{Apps: []App{{Kind: AppExe, Value: "steam.exe"}}}
	cfg.Blocks = []Block{{ID: "hard", Apps: []string{"steam.exe"}}}
	_ = cfg.ActiveAt(at(20, 19, 0))
	if read {
		t.Error("a config with no limits read the usage ledger")
	}
}

// The plain resolution path - what the CLI and the status window use - has to pick
// the limit up on its own, or a caller that knows nothing about limits would
// silently treat every budget as untouched.
func TestActiveAtReadsTheLedgerItself(t *testing.T) {
	stubLedger(t, map[string]time.Duration{"games": 45 * time.Minute}, usage.StateOK)
	cfg := limitedConfig()
	if got := len(cfg.ActiveAt(at(20, 19, 0)).BlockedApps()); got != 2 {
		t.Errorf("%d apps blocked, want 2 - the spent budget was not picked up", got)
	}

	stubLedger(t, map[string]time.Duration{"games": time.Minute}, usage.StateOK)
	if got := len(cfg.ActiveAt(at(20, 19, 0)).BlockedApps()); got != 1 {
		t.Errorf("%d apps blocked, want 1 - the remaining budget was not honoured", got)
	}
}

func TestSpentAtFailsClosedOnAnUnreadableLedger(t *testing.T) {
	stubLedger(t, nil, usage.StateUnreadable)
	cfg := limitedConfig()
	sp := cfg.SpentAt(at(20, 19, 0))
	if !sp.Unreadable {
		t.Fatal("SpentAt did not report the ledger as unreadable")
	}
	if got := len(cfg.ActiveAt(at(20, 19, 0)).BlockedApps()); got != 2 {
		t.Errorf("%d apps blocked, want 2 - an unreadable ledger must fail closed", got)
	}
}

// What counts towards a limit: the apps the block covers that are switched on, out
// of the unresolved config. Reading the resolved one would stop the counting the
// moment there was budget to count against.
func TestMeasuredAppsCoversWhatTheBlockNames(t *testing.T) {
	cfg := limitedConfig()
	measured := cfg.MeasuredApps(cfg.Blocks[0])
	if len(measured) != 1 || measured[0].Value != "steam.exe" {
		t.Errorf("measured = %+v, want steam.exe", measured)
	}

	cfg.Apps[0].Disabled = true
	if got := cfg.MeasuredApps(cfg.Blocks[0]); len(got) != 0 {
		t.Errorf("measured = %+v, want nothing once the rule is switched off", got)
	}
}

func TestRunningLimitedNamesBlocksInUse(t *testing.T) {
	cfg := limitedConfig()
	now := at(20, 19, 0)
	procs := []Process{{PID: 100, Name: "steam.exe"}, {PID: 101, Name: "notepad.exe"}}

	if got := cfg.RunningLimited(now, procs); len(got) != 1 || got[0] != "games" {
		t.Errorf("RunningLimited = %v, want [games]", got)
	}
	if got := cfg.RunningLimited(now, []Process{{PID: 101, Name: "notepad.exe"}}); len(got) != 0 {
		t.Errorf("RunningLimited = %v, want nothing", got)
	}
	// Two copies of the same game do not spend the budget twice as fast.
	twice := cfg.RunningLimited(now, []Process{{PID: 1, Name: "steam.exe"}, {PID: 2, Name: "steam.exe"}})
	if len(twice) != 1 {
		t.Errorf("RunningLimited = %v, want one entry for one block", twice)
	}
}

// Out-of-window time is not charged: a block with a window and a limit means "this
// much during these hours", so use at an hour it does not apply to is not spending
// a budget that only applies later.
func TestRunningLimitedIgnoresOutOfWindowTime(t *testing.T) {
	cfg := limitedConfig()
	cfg.Blocks[0].Windows = []Window{{Start: "18:00", End: "22:00"}}
	procs := []Process{{PID: 100, Name: "steam.exe"}}

	if got := cfg.RunningLimited(at(20, 19, 0), procs); len(got) != 1 {
		t.Errorf("in window: %v, want [games]", got)
	}
	if got := cfg.RunningLimited(at(20, 9, 0), procs); len(got) != 0 {
		t.Errorf("out of window: %v, want nothing", got)
	}
}

// Nothing to measure means no process snapshot at all, and a snapshot asks for the
// expensive parts only when a rule is matched on them.
func TestMeasurementNeedsAsksForTheLeast(t *testing.T) {
	// No application rule of any kind is the only case that measures nothing. This
	// is every install that locks extensions and blocks sites, and it must keep
	// paying nothing for a process walk.
	none := Config{Extensions: []Extension{{Name: "blocknsfw"}}, Domains: []Domain{{Name: "reddit.com"}}}
	if measure, _ := none.MeasurementNeeds(at(20, 19, 0)); measure {
		t.Error("a config with no application rules wants to measure")
	}

	// An app rule and no limit does measure, because the record behind `guard usage`
	// is taken from the same sample - which is what gives a machine that blocks
	// Steam outright a history instead of nothing.
	plain := Config{Apps: []App{{Kind: AppExe, Value: "steam.exe"}}}
	if measure, _ := plain.MeasurementNeeds(at(20, 19, 0)); !measure {
		t.Error("an app rule with no limit does not want to measure, so it would have no record")
	}

	cfg := limitedConfig()
	measure, needs := cfg.MeasurementNeeds(at(20, 19, 0))
	if !measure {
		t.Error("a limited block in window does not want to measure")
	}
	// A bare image-name rule now asks for the name compiled into the executable,
	// so that renaming steam.exe does not hand back an unlimited evening - and
	// reading that name requires the image path. This is the one place the cost of
	// closing the rename bypass shows up: the cheapest kind of rule stopped being
	// free. It does not ask for window titles, which nothing here is matched on.
	if !needs.Originals {
		t.Error("a bare image-name rule did not ask for the compiled-in name")
	}
	if !needs.WantPaths() {
		t.Error("asking for compiled-in names did not imply asking for paths")
	}
	if needs.Titles {
		t.Error("a bare image-name rule asked for window titles")
	}

	cfg.Apps = append(cfg.Apps, App{Kind: AppTitle, Value: "Solitaire"})
	cfg.Blocks[0].Apps = append(cfg.Blocks[0].Apps, "Solitaire")
	if _, needs := cfg.MeasurementNeeds(at(20, 19, 0)); !needs.Titles {
		t.Error("a window-title rule under a limit did not ask for titles")
	}

	// A limit covering only a folder rule wants paths, and has no bare name to
	// need a compiled-in one for.
	folder := limitedConfig()
	folder.Apps = []App{{Kind: AppFolder, Value: `C:\Games\Steam`}}
	folder.Blocks[0].Apps = []string{`C:\Games\Steam`}
	_, folderNeeds := folder.MeasurementNeeds(at(20, 19, 0))
	if !folderNeeds.Paths {
		t.Error("a folder rule under a limit did not ask for paths")
	}
	if folderNeeds.Originals {
		t.Error("a folder rule asked for compiled-in names, which cannot help it")
	}

	// Out of window the *budget* is not charged - RunningLimited above is what holds
	// that - but the rule is still switched on, so the record still wants the sample.
	// The two conditions differ on purpose: a limit is a budget for those hours, and
	// a record is a record of an hour spent.
	windowed := limitedConfig()
	windowed.Blocks[0].Windows = []Window{{Start: "18:00", End: "22:00"}}
	if measure, _ := windowed.MeasurementNeeds(at(20, 9, 0)); !measure {
		t.Error("an out-of-window limit measures nothing, so its rules would have no record")
	}
	if got := windowed.RunningLimited(at(20, 9, 0), []Process{{PID: 1, Name: "steam.exe"}}); len(got) != 0 {
		t.Errorf("out of window the budget was charged: %v", got)
	}
}

func TestHumanDurationReadsLikeAPersonSaysIt(t *testing.T) {
	cases := map[time.Duration]string{
		0:                           "0m",
		30 * time.Second:            "under a minute",
		time.Minute:                 "1m",
		45 * time.Minute:            "45m",
		time.Hour:                   "1h",
		90 * time.Minute:            "1h30m",
		2*time.Hour + 5*time.Minute: "2h5m",
		-time.Minute:                "0m",
	}
	for in, want := range cases {
		if got := HumanDuration(in); got != want {
			t.Errorf("HumanDuration(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestLimitSummaryDescribesTheBudget(t *testing.T) {
	if got := (Block{ID: "games", Limit: "90"}).LimitSummary(); got != "1h30m/day" {
		t.Errorf("LimitSummary = %q, want 1h30m/day", got)
	}
	if got := (Block{ID: "hard"}).LimitSummary(); got != "" {
		t.Errorf("LimitSummary for a block with no limit = %q, want empty", got)
	}
}

// A config without limits has to encode exactly as it did before they existed, or
// every installed machine would see its trusted copy change on upgrade and read it
// as tamper.
func TestLimitFieldsAreAbsentWhenUnused(t *testing.T) {
	cfg := Config{
		Extensions: []Extension{{Name: "sieve", Chrome: Target{ExtensionID: "a", UpdateURL: "https://u"}}},
		Blocks:     []Block{{ID: "hard"}},
	}
	canon, err := cfg.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	for _, field := range []string{"limit", "resetAt"} {
		if strings.Contains(string(canon), field) {
			t.Errorf("canonical encoding mentions %q for a config that uses no limits:\n%s", field, canon)
		}
	}
}

// The round trip a hand-edited config goes through: written by a person, parsed,
// and enforced. It is the path `guard commit` takes, and the limit has to survive
// it in both directions.
func TestLimitSurvivesTheConfigRoundTrip(t *testing.T) {
	cfg := limitedConfig()
	cfg.ResetAt = "04:00"
	canon, err := cfg.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	var loaded Config
	if err := loaded.UnmarshalJSON(canon); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if loaded.ResetAt != "04:00" {
		t.Errorf("resetAt did not survive: %q", loaded.ResetAt)
	}
	if len(loaded.Blocks) != 1 || loaded.Blocks[0].Limit != "45m" {
		t.Fatalf("the limit did not survive: %+v", loaded.Blocks)
	}
	if got := len(loaded.ActiveAtWith(at(20, 19, 0), spentOf(map[string]time.Duration{"games": time.Hour})).BlockedApps()); got != 2 {
		t.Errorf("%d apps blocked after the round trip, want 2", got)
	}
}
