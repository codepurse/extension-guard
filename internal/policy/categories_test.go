package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// socialCat is the catalog entry the tests exercise. Reading it from the catalog
// rather than building a fixture is deliberate: these tests should fail if the
// shipped social category is ever given a shape - a folder rule, a two-character
// title - that the rest of the guard refuses.
func socialCat(t *testing.T) Category {
	t.Helper()
	cat, ok := LookupCategory("social")
	if !ok {
		t.Fatal("the social category is missing from the catalog")
	}
	return cat
}

// The shipped catalog has to obey its own rules, and ValidateCatalog is where
// they are written down. This test is the thing that stops a plausible-looking
// entry - a window title, a folder broad enough to hold anything, an executable
// name a dozen programs share - reaching a user who never inspected it.
func TestCatalogObeysItsOwnRules(t *testing.T) {
	if err := ValidateCatalog(); err != nil {
		t.Fatalf("the shipped catalog is not shippable: %v", err)
	}
}

// Every catalog entry must also be applicable, which is a stronger claim than
// being well-formed: AddApp refuses things NormalizeApp accepts, so a rule can
// validate and still be impossible to add.
func TestEveryCatalogEntryCanActuallyBeApplied(t *testing.T) {
	for _, id := range CategoryIDs() {
		cat, _ := LookupCategory(id)
		var cfg Config
		res, err := cfg.ApplyCategory(cat)
		if err != nil {
			t.Errorf("category %q could not be applied: %v", id, err)
			continue
		}
		if len(res.Skipped) != 0 {
			t.Errorf("category %q skipped entries on a clean config: %v", id, res.Skipped)
		}
		if got, want := len(cfg.Apps), len(cat.Apps); got != want {
			t.Errorf("category %q added %d rules, want %d", id, got, want)
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("category %q produced a config that does not validate: %v", id, err)
		}
	}
}

func TestFolderDepthMeasuresHowBroadAFolderRuleIs(t *testing.T) {
	cases := map[string]int{
		`C:\Program Files\Google\Play Games`: 3,
		`C:\Program Files\Rockstar Games`:    2,
		`C:\Program Files`:                   1,
		`C:\Games`:                           1,
		`C:\`:                                0,
		`C:`:                                 0,
	}
	for in, want := range cases {
		if got := folderDepth(in); got != want {
			t.Errorf("folderDepth(%q) = %d, want %d", in, got, want)
		}
	}
	// The rule the catalog is held to: a vendor directory passes, a bare
	// top-level folder that could hold anything does not.
	if folderDepth(`C:\Games`) >= catalogFolderDepth {
		t.Error(`C:\Games would be accepted as a catalog folder rule`)
	}
	if folderDepth(`C:\Program Files\Rockstar Games\Launcher`) < catalogFolderDepth {
		t.Error("a real vendor directory was rejected")
	}
}

func TestApplyCategoryExpandsAppsDomainsAndABlock(t *testing.T) {
	cat := socialCat(t)
	var cfg Config
	res, err := cfg.ApplyCategory(cat)
	if err != nil {
		t.Fatalf("ApplyCategory: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the expanded config does not validate: %v", err)
	}
	if len(cfg.Apps) != len(cat.Apps) {
		t.Errorf("%d rules added, want %d", len(cfg.Apps), len(cat.Apps))
	}
	if len(cfg.Domains) != len(cat.Domains) {
		t.Errorf("%d domains added, want %d", len(cfg.Domains), len(cat.Domains))
	}
	if !res.NewBlock || len(cfg.Blocks) != 1 {
		t.Fatalf("want one new block, got %d (new=%v)", len(cfg.Blocks), res.NewBlock)
	}
	block := cfg.Blocks[0]
	if block.ID != cat.ID || block.Label != cat.Label {
		t.Errorf("block is %q/%q, want %q/%q", block.ID, block.Label, cat.ID, cat.Label)
	}
	// The whole point of the always-on shape: a category adds protection and
	// nothing else, so it costs no password. Narrows() is what add-block asks.
	if block.Narrows() {
		t.Error("a category block narrows protection; it must be around the clock")
	}
	if len(block.Windows) != 0 || block.Limit != "" {
		t.Errorf("category block carries a schedule or limit: %+v", block)
	}
}

func TestApplyCategoryStampsItsSource(t *testing.T) {
	cat := socialCat(t)
	var cfg Config
	if _, err := cfg.ApplyCategory(cat); err != nil {
		t.Fatalf("ApplyCategory: %v", err)
	}
	for _, a := range cfg.Apps {
		if a.Source != cat.Source() {
			t.Errorf("rule %q has source %q, want %q", a.Value, a.Source, cat.Source())
		}
	}
	for _, d := range cfg.Domains {
		if d.Source != cat.Source() {
			t.Errorf("domain %q has source %q, want %q", d.Name, d.Source, cat.Source())
		}
	}
	byKey := cfg.AppCategories()
	if len(byKey) != len(cfg.Apps) {
		t.Errorf("AppCategories reported %d rules, want %d", len(byKey), len(cfg.Apps))
	}
	for _, got := range byKey {
		if got != cat.ID {
			t.Errorf("AppCategories reported %q, want %q", got, cat.ID)
		}
	}
}

func TestApplyCategoryTwiceChangesNothing(t *testing.T) {
	cat := socialCat(t)
	var cfg Config
	if _, err := cfg.ApplyCategory(cat); err != nil {
		t.Fatalf("first ApplyCategory: %v", err)
	}
	apps, domains, blocks := len(cfg.Apps), len(cfg.Domains), len(cfg.Blocks)

	res, err := cfg.ApplyCategory(cat)
	if err != nil {
		t.Fatalf("second ApplyCategory: %v", err)
	}
	if res.Changed() {
		t.Errorf("re-applying reported a change: %+v", res)
	}
	if len(cfg.Apps) != apps || len(cfg.Domains) != domains || len(cfg.Blocks) != blocks {
		t.Errorf("re-applying grew the config: %d/%d/%d, want %d/%d/%d",
			len(cfg.Apps), len(cfg.Domains), len(cfg.Blocks), apps, domains, blocks)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("config invalid after re-applying: %v", err)
	}
}

// A catalog that gains an entry must be reachable by re-running the command,
// since nothing resolves the catalog at enforcement time. This is that path.
func TestApplyCategoryTopsUpAnExistingBlock(t *testing.T) {
	cat := socialCat(t)
	trimmed := cat
	trimmed.Apps = cat.Apps[:2]
	trimmed.Domains = cat.Domains[:2]

	var cfg Config
	if _, err := cfg.ApplyCategory(trimmed); err != nil {
		t.Fatalf("ApplyCategory (trimmed): %v", err)
	}
	// Standing in for a scheduled, locked category: topping up must widen it
	// rather than being refused, because widening only strengthens.
	cfg.Blocks[0].Windows = []Window{{Start: "09:00", End: "17:00"}}

	res, err := cfg.ApplyCategory(cat)
	if err != nil {
		t.Fatalf("ApplyCategory (full): %v", err)
	}
	if res.NewBlock {
		t.Error("topping up created a second block instead of widening the first")
	}
	if len(cfg.Blocks) != 1 {
		t.Fatalf("%d blocks, want 1", len(cfg.Blocks))
	}
	block := cfg.Blocks[0]
	if len(block.Apps) != len(cat.Apps) || len(block.Domains) != len(cat.Domains) {
		t.Errorf("block governs %d apps and %d domains, want %d and %d",
			len(block.Apps), len(block.Domains), len(cat.Apps), len(cat.Domains))
	}
	if len(block.Windows) != 1 {
		t.Error("topping up dropped the schedule the user had set")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("config invalid after topping up: %v", err)
	}
}

// A rule somebody added by hand keeps its own provenance when a category later
// names it, so a refresh cannot decide it owns - and may remove - an entry the
// user made themselves.
func TestApplyCategoryLeavesAHandAddedRuleUnclaimed(t *testing.T) {
	cat := socialCat(t)
	var cfg Config
	if _, _, err := cfg.AddApp(AppExe, "Discord.exe", "Discord"); err != nil {
		t.Fatalf("AddApp: %v", err)
	}
	if _, err := cfg.ApplyCategory(cat); err != nil {
		t.Fatalf("ApplyCategory: %v", err)
	}
	for _, a := range cfg.Apps {
		if strings.EqualFold(a.Value, "Discord.exe") && a.Source != "" {
			t.Errorf("the hand-added rule was claimed by %q", a.Source)
		}
	}
}

// The trusted-copy check compares bytes, so a config written before categories
// existed must encode exactly as it did then. If Source ever loses omitempty
// this fails, and every installed machine would fail its integrity check on
// upgrade.
func TestSourceIsAbsentFromAConfigThatHasNone(t *testing.T) {
	cfg := Config{
		Apps:    []App{{Kind: AppExe, Value: "steam.exe"}},
		Domains: []Domain{{Name: "reddit.com"}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), "source") {
		t.Errorf("a config with no categories encoded a source field: %s", data)
	}
}

func TestSourceSurvivesTheConfigRoundTrip(t *testing.T) {
	cat := socialCat(t)
	var cfg Config
	if _, err := cfg.ApplyCategory(cat); err != nil {
		t.Fatalf("ApplyCategory: %v", err)
	}
	canon, err := cfg.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	var loaded Config
	if err := loaded.UnmarshalJSON(canon); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if len(loaded.Apps) != len(cfg.Apps) {
		t.Fatalf("%d rules after the round trip, want %d", len(loaded.Apps), len(cfg.Apps))
	}
	for _, a := range loaded.Apps {
		if a.Source != cat.Source() {
			t.Errorf("rule %q lost its source: %q", a.Value, a.Source)
		}
	}
	for _, d := range loaded.Domains {
		if d.Source != cat.Source() {
			t.Errorf("domain %q lost its source: %q", d.Name, d.Source)
		}
	}
}

func TestLookupCategoryIsCaseInsensitiveAndRefusesTheUnknown(t *testing.T) {
	if _, ok := LookupCategory("  SOCIAL "); !ok {
		t.Error("LookupCategory did not match a padded, upper-case id")
	}
	if _, ok := LookupCategory("nonesuch"); ok {
		t.Error("LookupCategory invented a category")
	}
}

func TestGenericNamesAreRefusedByNameAndAllowedByPath(t *testing.T) {
	// Both are real: Google Play Games launches client.exe and the Rockstar
	// Games Launcher launches Launcher.exe.
	for _, name := range []string{"client.exe", "Launcher.exe", "javaw.exe", "update.exe"} {
		var cfg Config
		if _, _, err := cfg.AddApp(AppExe, name, ""); err == nil {
			t.Errorf("%q was accepted as a bare name", name)
		}
	}
	// The same program named unambiguously is fine - refusing this would leave
	// no way to block Google Play Games at all.
	var cfg Config
	if _, _, err := cfg.AddApp(AppExe, `C:\Program Files\Google\Play Games\client.exe`, ""); err != nil {
		t.Errorf("a full path to a generic name was refused: %v", err)
	}
	if _, _, err := cfg.AddApp(AppFolder, `C:\Program Files\Rockstar Games\Launcher`, ""); err != nil {
		t.Errorf("a folder rule covering a generic name was refused: %v", err)
	}
	// Blocking the terminal by name is a real intent, not a mistake.
	if _, _, err := cfg.AddApp(AppExe, "cmd.exe", ""); err != nil {
		t.Errorf("cmd.exe was refused: %v", err)
	}
}

// The check lives in AddApp, not in Validate, so that a config already holding a
// generic bare name keeps loading - and keeps its schedule. Getting this wrong
// would turn every scheduled block such a user had into an always-on one on the
// next upgrade, which is the loudest possible way to break a working install.
func TestAConfigHoldingAGenericNameStillValidates(t *testing.T) {
	cfg := Config{
		Apps:   []App{{Kind: AppExe, Value: "launcher.exe"}},
		Blocks: []Block{{ID: "games", Apps: []string{"launcher.exe"}, Windows: []Window{{Start: "09:00", End: "17:00"}}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("an existing config with a generic name stopped validating: %v", err)
	}
	if _, err := cfg.EnforcedAt(at(20, 12, 0)); err != nil {
		t.Errorf("EnforcedAt refused it, so the schedule would be ignored: %v", err)
	}
}

// CategoryMissing is what the status window's button reads: "Block" when there
// is something to add, "Top up (3)" after the catalog grew, and a disabled
// button when pressing it would change nothing. Getting it wrong shows the user
// a button that does nothing, which teaches them their clicks are not connected.
func TestCategoryMissingCountsWhatWouldBeAdded(t *testing.T) {
	cat := socialCat(t)
	total := len(cat.Apps) + len(cat.Domains)

	var empty Config
	if got := empty.CategoryMissing(cat); got != total {
		t.Errorf("on an empty config: %d missing, want %d", got, total)
	}

	full := Config{}
	if _, err := full.ApplyCategory(cat); err != nil {
		t.Fatalf("ApplyCategory: %v", err)
	}
	if got := full.CategoryMissing(cat); got != 0 {
		t.Errorf("after applying: %d missing, want 0", got)
	}

	// A rule the user switched off is still in the list, and re-applying leaves it
	// off. Counting it as missing would promise an addition the button cannot make.
	off := full
	off.Apps = append([]App(nil), full.Apps...)
	off.Apps[0].Disabled = true
	if got := off.CategoryMissing(cat); got != 0 {
		t.Errorf("with one entry switched off: %d missing, want 0", got)
	}

	// The state a user lands in when an update adds entries to a category they
	// already blocked.
	partial := Config{}
	trimmed := cat
	trimmed.Apps = cat.Apps[:3]
	trimmed.Domains = nil
	if _, err := partial.ApplyCategory(trimmed); err != nil {
		t.Fatalf("ApplyCategory (trimmed): %v", err)
	}
	if got, want := partial.CategoryMissing(cat), total-3; got != want {
		t.Errorf("after a partial apply: %d missing, want %d", got, want)
	}
}

// The contents list is what a person reads before agreeing to a category, so it
// has to name every entry and be honest about which are already blocked. A list
// that showed twenty-eight new restrictions when three were new would push
// somebody away from a top-up that costs them almost nothing.
func TestCategoryEntriesListEverythingAndMarkWhatIsHeld(t *testing.T) {
	cat := socialCat(t)

	var empty Config
	entries := empty.CategoryEntries(cat)
	if len(entries) != len(cat.Apps)+len(cat.Domains) {
		t.Fatalf("%d entries, want %d", len(entries), len(cat.Apps)+len(cat.Domains))
	}
	apps, sites := 0, 0
	for _, e := range entries {
		switch e.Kind {
		case EntryApp:
			apps++
		case EntrySite:
			sites++
		default:
			t.Errorf("entry %q has kind %q", e.Label, e.Kind)
		}
		if e.Label == "" {
			t.Errorf("entry %q has no label to show", e.Value)
		}
		if e.Present {
			t.Errorf("%q is marked present on an empty config", e.Label)
		}
	}
	if apps != len(cat.Apps) || sites != len(cat.Domains) {
		t.Errorf("%d apps and %d sites, want %d and %d", apps, sites, len(cat.Apps), len(cat.Domains))
	}

	// One site blocked by hand beforehand: it must come back marked, and it must
	// be the only one. This is the reddit.com case on a real machine.
	var partial Config
	if _, _, err := partial.AddDomain(cat.Domains[0]); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	held := 0
	for _, e := range partial.CategoryEntries(cat) {
		if e.Present {
			held++
			if e.Label != cat.Domains[0] {
				t.Errorf("%q is marked present, want only %q", e.Label, cat.Domains[0])
			}
		}
	}
	if held != 1 {
		t.Errorf("%d entries marked present, want 1", held)
	}

	// The count under the button and the marks in the list are two renderings of
	// the same fact, and a user comparing them will notice if they disagree.
	full := Config{}
	if _, err := full.ApplyCategory(cat); err != nil {
		t.Fatalf("ApplyCategory: %v", err)
	}
	absent := 0
	for _, e := range full.CategoryEntries(cat) {
		if !e.Present {
			absent++
		}
	}
	if absent != full.CategoryMissing(cat) {
		t.Errorf("%d entries unmarked but CategoryMissing says %d", absent, full.CategoryMissing(cat))
	}
}
