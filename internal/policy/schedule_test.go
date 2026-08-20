package policy

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixture week: 2026-08-17 is a Monday, so day-of-week arithmetic in these
// tests is readable rather than computed.
func at(day, hour, minute int) time.Time {
	return time.Date(2026, 8, day, hour, minute, 0, 0, time.Local)
}

// TestFixtureWeekdays is a guard on the fixture itself: if these drift, every
// schedule assertion below silently starts testing the wrong day.
func TestFixtureWeekdays(t *testing.T) {
	want := map[int]time.Weekday{
		17: time.Monday, 18: time.Tuesday, 19: time.Wednesday, 20: time.Thursday,
		21: time.Friday, 22: time.Saturday, 23: time.Sunday,
	}
	for day, wd := range want {
		if got := at(day, 12, 0).Weekday(); got != wd {
			t.Errorf("2026-08-%02d is %v, fixture assumes %v", day, got, wd)
		}
	}
}

func TestWindowWithinOneDay(t *testing.T) {
	w := Window{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Start: "09:00", End: "17:00"}

	cases := []struct {
		name string
		when time.Time
		want bool
	}{
		{"before start", at(17, 8, 59), false},
		{"exactly at start", at(17, 9, 0), true},
		{"midday", at(17, 12, 30), true},
		{"one minute before end", at(17, 16, 59), true},
		{"exactly at end", at(17, 17, 0), false},
		{"after end", at(17, 18, 0), false},
		{"weekend, same hours", at(22, 12, 0), false},
	}
	for _, c := range cases {
		if got := w.Active(c.when); got != c.want {
			t.Errorf("%s: Active(%v) = %v, want %v", c.name, c.when, got, c.want)
		}
	}
}

// TestWindowOvernight is the case most likely to be wrong: a window whose end is
// before its start belongs to the day it *started* on, so the small hours of the
// following morning are still inside it.
func TestWindowOvernight(t *testing.T) {
	w := Window{Days: []string{"fri"}, Start: "22:00", End: "06:00"}

	cases := []struct {
		name string
		when time.Time
		want bool
	}{
		{"friday before start", at(21, 21, 59), false},
		{"friday at start", at(21, 22, 0), true},
		{"friday late", at(21, 23, 30), true},
		{"saturday small hours, still friday's window", at(22, 3, 0), true},
		{"saturday one minute before end", at(22, 5, 59), true},
		{"saturday at end", at(22, 6, 0), false},
		{"saturday daytime", at(22, 12, 0), false},
		{"saturday night is not covered, only friday starts one", at(22, 23, 0), false},
		{"sunday small hours, no saturday window to belong to", at(23, 3, 0), false},
	}
	for _, c := range cases {
		if got := w.Active(c.when); got != c.want {
			t.Errorf("%s: Active(%v) = %v, want %v", c.name, c.when, got, c.want)
		}
	}
}

func TestWindowEveryDayWhenNoDaysListed(t *testing.T) {
	w := Window{Start: "09:00", End: "17:00"}
	for day := 17; day <= 23; day++ {
		if !w.Active(at(day, 12, 0)) {
			t.Errorf("2026-08-%02d midday should be active when no days are listed", day)
		}
	}
}

func TestWindowUnparseableIsInactive(t *testing.T) {
	for _, w := range []Window{
		{Start: "9am", End: "17:00"},
		{Start: "09:00", End: "nope"},
		{Start: "25:00", End: "26:00"},
		{Start: "09:61", End: "17:00"},
		{Start: "", End: ""},
	} {
		if w.Active(at(17, 12, 0)) {
			t.Errorf("window %+v should not be active", w)
		}
	}
}

func TestBlockWithNoWindowsIsAlwaysActive(t *testing.T) {
	b := Block{ID: "always"}
	for day := 17; day <= 23; day++ {
		for _, hour := range []int{0, 6, 12, 23} {
			if !b.Active(at(day, hour, 0)) {
				t.Fatalf("a block with no windows should always be active (day %d, hour %d)", day, hour)
			}
		}
	}
}

func TestBlockActiveIfAnyWindowMatches(t *testing.T) {
	b := Block{ID: "split", Windows: []Window{
		{Days: []string{"mon"}, Start: "09:00", End: "12:00"},
		{Days: []string{"mon"}, Start: "14:00", End: "17:00"},
	}}
	if !b.Active(at(17, 10, 0)) {
		t.Error("morning window should be active")
	}
	if b.Active(at(17, 13, 0)) {
		t.Error("the lunch gap should not be active")
	}
	if !b.Active(at(17, 15, 0)) {
		t.Error("afternoon window should be active")
	}
}

func scheduledConfig() Config {
	return Config{
		Extensions: []Extension{
			{Name: "sieve", Chrome: Target{ExtensionID: "a", UpdateURL: "https://u"}},
			{Name: "blocknsfw", Chrome: Target{ExtensionID: "b", UpdateURL: "https://u"}},
		},
		Blocks: []Block{{
			ID:         "work",
			Extensions: []string{"sieve"},
			Windows:    []Window{{Days: []string{"mon"}, Start: "09:00", End: "17:00"}},
		}},
	}
}

func enabledNames(c Config) []string {
	var out []string
	for _, e := range c.Extensions {
		if !e.Disabled {
			out = append(out, e.Name)
		}
	}
	return out
}

// TestActiveAtGovernedVsUngoverned is the core resolution rule: a block narrows
// only the extensions it names, and everything else keeps enforcing as before.
func TestActiveAtGovernedVsUngoverned(t *testing.T) {
	cfg := scheduledConfig()

	inside := enabledNames(cfg.ActiveAt(at(17, 10, 0)))
	if len(inside) != 2 {
		t.Errorf("inside the window both should enforce, got %v", inside)
	}

	outside := enabledNames(cfg.ActiveAt(at(17, 20, 0)))
	if len(outside) != 1 || outside[0] != "blocknsfw" {
		t.Errorf("outside the window only the ungoverned extension should enforce, got %v", outside)
	}
}

// TestActiveAtLeavesDisabledAlone: a schedule narrows enforcement, it never
// widens it. An extension switched off outright stays off inside a window.
func TestActiveAtLeavesDisabledAlone(t *testing.T) {
	cfg := scheduledConfig()
	cfg.Extensions[0].Disabled = true

	if got := enabledNames(cfg.ActiveAt(at(17, 10, 0))); len(got) != 1 || got[0] != "blocknsfw" {
		t.Errorf("a disabled extension must stay disabled inside its window, got %v", got)
	}
}

// TestActiveAtDoesNotMutateReceiver guards the copy in ActiveAt: the service
// holds one Config across ticks, and a resolution that mutated it would make the
// first schedule boundary permanent.
func TestActiveAtDoesNotMutateReceiver(t *testing.T) {
	cfg := scheduledConfig()
	_ = cfg.ActiveAt(at(17, 20, 0)) // outside the window: would disable "sieve"

	if got := enabledNames(cfg); len(got) != 2 {
		t.Errorf("ActiveAt mutated its receiver: %v", got)
	}
	if got := enabledNames(cfg.ActiveAt(at(17, 10, 0))); len(got) != 2 {
		t.Errorf("resolving inside the window after resolving outside gave %v", got)
	}
}

// TestActiveAtWithNoBlocksIsIdentity is the compatibility guarantee: every
// install predating schedules must behave exactly as it did.
func TestActiveAtWithNoBlocksIsIdentity(t *testing.T) {
	cfg := Config{Extensions: []Extension{
		{Name: "sieve"},
		{Name: "blocknsfw", Disabled: true},
	}}
	got := cfg.ActiveAt(at(17, 3, 0))
	if len(got.Extensions) != 2 || got.Extensions[0].Disabled || !got.Extensions[1].Disabled {
		t.Errorf("a config with no blocks should resolve to itself, got %+v", got.Extensions)
	}
}

// TestBlockWithNoExtensionsGovernsEverything covers the "block everything on this
// schedule" shorthand.
func TestBlockWithNoExtensionsGovernsEverything(t *testing.T) {
	cfg := scheduledConfig()
	cfg.Blocks = []Block{{
		ID:      "quiet-hours",
		Windows: []Window{{Start: "22:00", End: "06:00"}},
	}}
	if got := enabledNames(cfg.ActiveAt(at(17, 23, 0))); len(got) != 2 {
		t.Errorf("inside quiet hours everything should enforce, got %v", got)
	}
	if got := enabledNames(cfg.ActiveAt(at(17, 12, 0))); len(got) != 0 {
		t.Errorf("outside quiet hours nothing should enforce, got %v", got)
	}
}

// TestActiveSignatureTracksBoundaries: the service ticks on this string, so it
// must differ across a boundary and be stable within a window.
func TestActiveSignatureTracksBoundaries(t *testing.T) {
	cfg := scheduledConfig()
	inside := cfg.ActiveSignature(at(17, 10, 0))
	alsoInside := cfg.ActiveSignature(at(17, 16, 59))
	outside := cfg.ActiveSignature(at(17, 20, 0))

	if inside != alsoInside {
		t.Errorf("signature changed within one window: %q vs %q", inside, alsoInside)
	}
	if inside == outside {
		t.Errorf("signature did not change across the boundary: %q", inside)
	}
}

func TestLockedAt(t *testing.T) {
	now := at(17, 12, 0)
	future := now.Add(48 * time.Hour).Format(time.RFC3339)
	past := now.Add(-1 * time.Hour).Format(time.RFC3339)

	if locked, _ := (Block{}).LockedAt(now); locked {
		t.Error("a block with no deadline should not be locked")
	}
	if locked, until := (Block{LockedUntil: future}).LockedAt(now); !locked || until.IsZero() {
		t.Error("a future deadline should be locked and report its time")
	}
	if locked, _ := (Block{LockedUntil: past}).LockedAt(now); locked {
		t.Error("a past deadline should no longer be locked")
	}
	// A corrupted deadline must fail closed, or editing it into nonsense would be
	// a way out of the lock.
	if locked, _ := (Block{LockedUntil: "sometime next week"}).LockedAt(now); !locked {
		t.Error("an unparseable deadline must count as locked")
	}
}

func TestLockedBlocks(t *testing.T) {
	now := at(17, 12, 0)
	cfg := Config{Blocks: []Block{
		{ID: "open"},
		{ID: "shut", LockedUntil: now.Add(24 * time.Hour).Format(time.RFC3339)},
		{ID: "expired", LockedUntil: now.Add(-24 * time.Hour).Format(time.RFC3339)},
	}}
	got := cfg.LockedBlocks(now)
	if len(got) != 1 || got[0].ID != "shut" {
		t.Errorf("LockedBlocks = %+v, want just the shut one", got)
	}
}

func TestValidate(t *testing.T) {
	base := func(blocks ...Block) Config {
		return Config{Extensions: []Extension{{Name: "sieve"}}, Blocks: blocks}
	}
	far := time.Now().Add(MaxLockDuration + 48*time.Hour).Format(time.RFC3339)

	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"valid", base(Block{ID: "a", Extensions: []string{"sieve"},
			Windows: []Window{{Days: []string{"mon"}, Start: "09:00", End: "17:00"}}}), ""},
		{"valid overnight", base(Block{ID: "a", Windows: []Window{{Start: "22:00", End: "06:00"}}}), ""},
		{"no blocks", base(), ""},
		{"missing id", base(Block{}), "no id"},
		{"duplicate id", base(Block{ID: "a"}, Block{ID: "A"}), "duplicate"},
		{"unknown extension", base(Block{ID: "a", Extensions: []string{"nope"}}), "unknown extension"},
		{"bad start", base(Block{ID: "a", Windows: []Window{{Start: "9", End: "17:00"}}}), "bad start"},
		{"bad end", base(Block{ID: "a", Windows: []Window{{Start: "09:00", End: "5pm"}}}), "bad end"},
		{"zero length", base(Block{ID: "a", Windows: []Window{{Start: "09:00", End: "09:00"}}}), "never applies"},
		{"unknown day", base(Block{ID: "a", Windows: []Window{{Days: []string{"funday"}, Start: "09:00", End: "17:00"}}}), "unknown day"},
		{"bad deadline", base(Block{ID: "a", LockedUntil: "next tuesday"}), "RFC 3339"},
		{"deadline too far", base(Block{ID: "a", LockedUntil: far}), "maximum"},
	}
	for _, c := range cases {
		err := c.cfg.Validate()
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.wantErr != "" && err == nil:
			t.Errorf("%s: expected an error containing %q", c.name, c.wantErr)
		case c.wantErr != "" && err != nil && !strings.Contains(err.Error(), c.wantErr):
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.wantErr)
		}
	}
}

// TestBlocksOmittedWhenEmpty is what keeps trusted copies written before
// schedules existed comparing equal after the upgrade: an empty Blocks must not
// appear in the canonical encoding.
func TestBlocksOmittedWhenEmpty(t *testing.T) {
	cfg := Config{Extensions: []Extension{{Name: "sieve"}}}
	canon, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canon), "blocks") {
		t.Errorf("canonical encoding mentions blocks when there are none:\n%s", canon)
	}
}

// TestBlocksRoundTrip checks the schema survives the custom UnmarshalJSON that
// also has to keep accepting the two older config shapes.
func TestBlocksRoundTrip(t *testing.T) {
	src := Config{
		Extensions: []Extension{{Name: "sieve", Chrome: Target{ExtensionID: "a", UpdateURL: "https://u"}}},
		Blocks: []Block{{
			ID:          "work",
			Label:       "Work hours",
			Extensions:  []string{"sieve"},
			Windows:     []Window{{Days: []string{"mon", "fri"}, Start: "09:00", End: "17:00"}},
			LockedUntil: "2026-09-01T09:00:00Z",
		}},
	}
	canon, err := src.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	var got Config
	if err := json.Unmarshal(canon, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Blocks) != 1 {
		t.Fatalf("got %d blocks, want 1", len(got.Blocks))
	}
	b := got.Blocks[0]
	if b.ID != "work" || b.Label != "Work hours" || b.LockedUntil != "2026-09-01T09:00:00Z" {
		t.Errorf("block round-tripped as %+v", b)
	}
	if len(b.Windows) != 1 || b.Windows[0].Start != "09:00" || len(b.Windows[0].Days) != 2 {
		t.Errorf("window round-tripped as %+v", b.Windows)
	}
}

// --- locked blocks ---------------------------------------------------------

func lockedCfg(until string) Config {
	return Config{
		Extensions: []Extension{{Name: "sieve"}, {Name: "blocknsfw"}},
		Blocks: []Block{{
			ID:          "work",
			Label:       "Work hours",
			Extensions:  []string{"sieve"},
			Windows:     []Window{{Days: []string{"mon"}, Start: "09:00", End: "17:00"}},
			LockedUntil: until,
		}},
	}
}

func TestCheckLockedBlocks(t *testing.T) {
	now := at(17, 12, 0)
	future := now.Add(48 * time.Hour).Format(time.RFC3339)
	further := now.Add(72 * time.Hour).Format(time.RFC3339)
	sooner := now.Add(1 * time.Hour).Format(time.RFC3339)
	past := now.Add(-1 * time.Hour).Format(time.RFC3339)

	current := lockedCfg(future)

	mutate := func(f func(*Config)) Config {
		c := lockedCfg(future)
		c.Blocks = append([]Block(nil), c.Blocks...)
		f(&c)
		return c
	}

	cases := []struct {
		name     string
		proposed Config
		wantErr  string
	}{
		{"unchanged", lockedCfg(future), ""},
		{"deadline extended", lockedCfg(further), ""},
		{"another block added", mutate(func(c *Config) {
			c.Blocks = append(c.Blocks, Block{ID: "extra"})
		}), ""},
		{"block removed", Config{Extensions: current.Extensions}, "cannot be removed"},
		{"deadline shortened", lockedCfg(sooner), "not shortened"},
		{"deadline removed", lockedCfg(""), "not shortened"},
		{"windows changed", mutate(func(c *Config) {
			c.Blocks[0].Windows = []Window{{Days: []string{"mon"}, Start: "10:00", End: "17:00"}}
		}), "cannot be changed"},
		{"a window dropped", mutate(func(c *Config) {
			c.Blocks[0].Windows = nil
		}), "cannot be changed"},
		{"days changed", mutate(func(c *Config) {
			c.Blocks[0].Windows[0].Days = []string{"sat"}
		}), "cannot be changed"},
		{"extensions changed", mutate(func(c *Config) {
			c.Blocks[0].Extensions = []string{"blocknsfw"}
		}), "cannot be changed"},
		{"label changed", mutate(func(c *Config) {
			c.Blocks[0].Label = "Something else"
		}), "cannot be changed"},
	}

	for _, c := range cases {
		err := CheckLockedBlocks(current, c.proposed, now)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected refusal: %v", c.name, err)
		case c.wantErr != "" && err == nil:
			t.Errorf("%s: expected a refusal mentioning %q", c.name, c.wantErr)
		case c.wantErr != "" && err != nil && !strings.Contains(err.Error(), c.wantErr):
			t.Errorf("%s: refusal %q does not mention %q", c.name, err, c.wantErr)
		}
	}

	// An expired lock stops constraining anything.
	if err := CheckLockedBlocks(lockedCfg(past), Config{}, now); err != nil {
		t.Errorf("an expired lock should not block a change: %v", err)
	}
	// A block that was never locked likewise.
	if err := CheckLockedBlocks(lockedCfg(""), Config{}, now); err != nil {
		t.Errorf("an unlocked block should not block a change: %v", err)
	}
}

// TestCheckLockedBlocksCorruptedDeadline: an unreadable deadline counts as
// locked, so the only accepted edit is one that supplies a readable future
// deadline. Otherwise mangling the timestamp would be the way out of a lock.
func TestCheckLockedBlocksCorruptedDeadline(t *testing.T) {
	now := time.Now()
	current := lockedCfg("whenever")

	if err := CheckLockedBlocks(current, lockedCfg(""), now); err == nil {
		t.Error("clearing a corrupted deadline should be refused")
	}
	if err := CheckLockedBlocks(current, lockedCfg("still not a time"), now); err == nil {
		t.Error("replacing one corrupted deadline with another should be refused")
	}
	good := now.Add(24 * time.Hour).Format(time.RFC3339)
	if err := CheckLockedBlocks(current, lockedCfg(good), now); err != nil {
		t.Errorf("supplying a readable future deadline should be accepted: %v", err)
	}
}

// --- display helpers -------------------------------------------------------

func TestWindowSummary(t *testing.T) {
	cases := []struct {
		w    Window
		want string
	}{
		{Window{Start: "09:00", End: "17:00"}, "Daily 09:00-17:00"},
		{Window{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Start: "09:00", End: "17:00"}, "Mon-Fri 09:00-17:00"},
		{Window{Days: []string{"sat", "sun"}, Start: "10:00", End: "23:00"}, "Weekends 10:00-23:00"},
		{Window{Days: []string{"mon", "wed", "fri"}, Start: "20:00", End: "22:00"}, "Mon Wed Fri 20:00-22:00"},
		// Listed out of order, and in long form: still reads Monday-first.
		{Window{Days: []string{"friday", "monday"}, Start: "08:00", End: "09:00"}, "Mon Fri 08:00-09:00"},
		{Window{Days: []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}, Start: "00:00", End: "23:59"}, "Daily 00:00-23:59"},
	}
	for _, c := range cases {
		if got := c.w.Summary(); got != c.want {
			t.Errorf("Summary() = %q, want %q", got, c.want)
		}
	}
}

func TestScheduleSummary(t *testing.T) {
	if got := (Block{}).ScheduleSummary(); got != "Always" {
		t.Errorf("a block with no windows summarised as %q, want Always", got)
	}
	b := Block{Windows: []Window{
		{Days: []string{"mon"}, Start: "09:00", End: "12:00"},
		{Days: []string{"mon"}, Start: "14:00", End: "17:00"},
	}}
	if got, want := b.ScheduleSummary(), "Mon 09:00-12:00, Mon 14:00-17:00"; got != want {
		t.Errorf("ScheduleSummary() = %q, want %q", got, want)
	}
}

func TestGovernedSummary(t *testing.T) {
	if got := (Block{}).GovernedSummary(); got != "everything" {
		t.Errorf("a block naming nothing summarised as %q, want everything", got)
	}
	if got := (Block{Extensions: []string{"sieve", "blocknsfw"}}).GovernedSummary(); got != "sieve, blocknsfw" {
		t.Errorf("got %q", got)
	}
	// Domains appear normalized, so the summary matches what is enforced.
	b := Block{Extensions: []string{"sieve"}, Domains: []string{"https://www.Reddit.com/r/x"}}
	if got, want := b.GovernedSummary(), "sieve, reddit.com"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestGovernedBy backs the "scheduled" tag in the status window: an extension
// under a block is enforced on a timetable, not around the clock, and the window
// has to be able to say so.
func TestGovernedBy(t *testing.T) {
	cfg := scheduledConfig() // block "work" governs only "sieve"
	if !cfg.GovernedBy("sieve") {
		t.Error("sieve is governed by the work block")
	}
	if cfg.GovernedBy("blocknsfw") {
		t.Error("blocknsfw is governed by nothing")
	}
	// A block with no extensions listed governs everything.
	cfg.Blocks = []Block{{ID: "all"}}
	if !cfg.GovernedBy("blocknsfw") {
		t.Error("a block with no extensions should govern every extension")
	}
	// And a config with no blocks governs nothing.
	cfg.Blocks = nil
	if cfg.GovernedBy("sieve") {
		t.Error("a config with no blocks governs nothing")
	}
}

// A schedule is the one kind of rule that makes enforcement *less* than
// around-the-clock, which is what the password gate on creating one keys off.
// An always-on block cannot weaken anything, so it must not read as narrowing.
func TestBlockNarrows(t *testing.T) {
	always := Block{ID: "commit"}
	if always.Narrows() {
		t.Error("a block with no windows is always on; it does not narrow enforcement")
	}
	scheduled := Block{ID: "work", Windows: []Window{{Start: "09:00", End: "17:00"}}}
	if !scheduled.Narrows() {
		t.Error("a block with a window enforces only sometimes, which narrows enforcement")
	}
}

func TestAddBlockRefusesDuplicateID(t *testing.T) {
	cfg := Config{Blocks: []Block{{ID: "work"}}}
	if err := cfg.AddBlock(Block{ID: "evenings"}); err != nil {
		t.Fatalf("AddBlock: %v", err)
	}
	if err := cfg.AddBlock(Block{ID: "WORK"}); err == nil {
		t.Error("expected a duplicate id to be refused, case-insensitively")
	}
	if err := cfg.AddBlock(Block{ID: "  "}); err == nil {
		t.Error("expected a block with no id to be refused")
	}
	if len(cfg.Blocks) != 2 {
		t.Errorf("config has %d blocks, want 2", len(cfg.Blocks))
	}
}

func TestRemoveBlock(t *testing.T) {
	cfg := Config{Blocks: []Block{{ID: "work"}, {ID: "evenings"}, {ID: "weekends"}}}
	if !cfg.RemoveBlock("EVENINGS") {
		t.Fatal("RemoveBlock did not find the block")
	}
	if len(cfg.Blocks) != 2 || cfg.Blocks[0].ID != "work" || cfg.Blocks[1].ID != "weekends" {
		t.Errorf("blocks after removal = %+v", cfg.Blocks)
	}
	if cfg.RemoveBlock("nope") {
		t.Error("RemoveBlock reported removing a block that was not there")
	}
}

// The id is derived so the status window can ask for a name and nothing else.
func TestNewBlockID(t *testing.T) {
	cases := map[string]string{
		"Work hours":     "work-hours",
		"  Evenings!!  ": "evenings",
		"Sat & Sun":      "sat-sun",
		"":               "block",
		"...":            "block",
		"A very long name indeed that keeps going": "a-very-long-name-indeed",
	}
	for label, want := range cases {
		if got := NewBlockID(label, nil); got != want {
			t.Errorf("NewBlockID(%q) = %q, want %q", label, got, want)
		}
	}
	// A collision gets a suffix rather than silently colliding.
	taken := map[string]bool{"work-hours": true, "work-hours-2": true}
	if got := NewBlockID("Work hours", func(id string) bool { return taken[id] }); got != "work-hours-3" {
		t.Errorf("NewBlockID with collisions = %q, want work-hours-3", got)
	}
}

// Removing a locked block is refused by the same check that refuses editing one:
// the promise a lock makes is that it outlasts the password.
func TestRemovingALockedBlockIsRefused(t *testing.T) {
	now := time.Now()
	locked := Block{ID: "focus", LockedUntil: now.Add(24 * time.Hour).Format(time.RFC3339)}
	current := Config{Blocks: []Block{locked, {ID: "other"}}}

	proposed := Config{Blocks: []Block{locked}} // "other" removed: fine
	if err := CheckLockedBlocks(current, proposed, now); err != nil {
		t.Errorf("removing an unlocked block should be allowed: %v", err)
	}
	proposed = Config{Blocks: []Block{{ID: "other"}}} // "focus" removed: refused
	if err := CheckLockedBlocks(current, proposed, now); err == nil {
		t.Error("expected removing a locked block to be refused")
	}
}

// TestAuthoredBlockSurvivesTheTrustedStore walks the whole path a block created
// from the status window takes: it is added to the enforced config, committed
// through the SYSTEM-owned store, reloaded the way the service reloads it, and
// then resolved against the clock.
//
// The last step is the one worth guarding. A block authored in the GUI has to
// behave exactly like one hand-written into the file - enforcing inside its
// window, releasing outside it - or the feature would look like it worked while
// enforcing something else entirely.
func TestAuthoredBlockSurvivesTheTrustedStore(t *testing.T) {
	store := &fakeStore{}
	useFakeStore(t, store)
	path := filepath.Join(t.TempDir(), "extension-ids.json")

	cfg := Config{
		Extensions: []Extension{{Name: "sieve"}},
		Domains:    []Domain{{Name: "reddit.com"}},
		Apps:       []App{{Kind: AppExe, Value: "steam.exe"}},
	}
	// What `guard add-block -label "Work hours" -days ... -from 09:00 -to 17:00`
	// builds, governing one thing of each kind.
	block := Block{
		ID:         NewBlockID("Work hours", nil),
		Label:      "Work hours",
		Extensions: []string{"sieve"},
		Domains:    []string{"reddit.com"},
		Apps:       []string{"steam.exe"},
		Windows:    []Window{{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Start: "09:00", End: "17:00"}},
	}
	if err := cfg.AddBlock(block); err != nil {
		t.Fatalf("AddBlock: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := Commit(cfg, path); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	loaded, trust, err := LoadTrusted(path)
	if err != nil {
		t.Fatalf("LoadTrusted: %v", err)
	}
	if trust != TrustOK {
		t.Errorf("trust = %v, want ok - a committed config must not read back as tampered", trust)
	}
	got, ok := loaded.Block("work-hours")
	if !ok {
		t.Fatalf("the block did not survive the round trip: %+v", loaded.Blocks)
	}
	if got.ScheduleSummary() != "Mon-Fri 09:00-17:00" {
		t.Errorf("schedule = %q", got.ScheduleSummary())
	}

	// Wednesday 10:00 is inside the window; Wednesday 20:00 is outside it.
	inside := time.Date(2026, 8, 19, 10, 0, 0, 0, time.Local)
	outside := time.Date(2026, 8, 19, 20, 0, 0, 0, time.Local)

	active, err := loaded.EnforcedAt(inside)
	if err != nil {
		t.Fatalf("EnforcedAt: %v", err)
	}
	if len(active.Targets(Chrome)) != 1 || len(active.BlockedDomains()) != 1 || len(active.BlockedApps()) != 1 {
		t.Errorf("inside the window: %d extensions, %d domains, %d apps enforced; want 1 each",
			len(active.Targets(Chrome)), len(active.BlockedDomains()), len(active.BlockedApps()))
	}
	idle, err := loaded.EnforcedAt(outside)
	if err != nil {
		t.Fatalf("EnforcedAt: %v", err)
	}
	if len(idle.Targets(Chrome)) != 0 || len(idle.BlockedDomains()) != 0 || len(idle.BlockedApps()) != 0 {
		t.Errorf("outside the window: %d extensions, %d domains, %d apps still enforced; want 0 each",
			len(idle.Targets(Chrome)), len(idle.BlockedDomains()), len(idle.BlockedApps()))
	}
	if loaded.ActiveSignature(inside) == loaded.ActiveSignature(outside) {
		t.Error("the signature does not change across the boundary, so the service would not re-apply")
	}
}
