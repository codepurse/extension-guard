package policy

import (
	"strings"
	"testing"
	"time"
)

// withSystemRoot pins the Windows directory for the duration of a test, so the
// folder guardrail is checked against a known value rather than against whatever
// machine the test runs on.
func withSystemRoot(t *testing.T, root string) {
	t.Helper()
	old := systemRootDir
	systemRootDir = root
	t.Cleanup(func() { systemRootDir = old })
}

func TestNormalizeAppExe(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  string
		fails bool
	}{
		{"full path", `C:\Games\Steam\steam.exe`, `C:\Games\Steam\steam.exe`, false},
		{"forward slashes", `C:/Games/Steam/steam.exe`, `C:\Games\Steam\steam.exe`, false},
		{"quoted, as Explorer copies it", `"C:\Games\steam.exe"`, `C:\Games\steam.exe`, false},
		{"bare name", "steam.exe", "steam.exe", false},
		{"bare name without extension", "steam", "steam.exe", false},
		{"case is kept", "Steam.EXE", "Steam.EXE", false},
		{"not an executable", `C:\Games\readme.txt`, "", true},
		{"partial path", `Games\steam.exe`, "", true},
		{"part of Windows", "explorer.exe", "", true},
		{"part of Windows, by path", `C:\Windows\explorer.exe`, "", true},
		{"empty", "   ", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeApp(AppExe, c.in, "")
		if c.fails {
			if err == nil {
				t.Errorf("%s: expected %q to be refused, got %+v", c.name, c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: NormalizeApp(%q) = %v", c.name, c.in, err)
			continue
		}
		if got.Value != c.want || got.Kind != AppExe {
			t.Errorf("%s: NormalizeApp(%q) = %+v, want value %q", c.name, c.in, got, c.want)
		}
	}
}

// An empty kind means "exe". A hand-written rule that names only a value is the
// obvious way to write one, and it must mean what its author meant.
func TestNormalizeAppDefaultsToExe(t *testing.T) {
	got, err := NormalizeApp("", "steam.exe", "")
	if err != nil {
		t.Fatalf("NormalizeApp: %v", err)
	}
	if got.Kind != AppExe {
		t.Errorf("kind = %q, want %q", got.Kind, AppExe)
	}
}

func TestNormalizeAppFolder(t *testing.T) {
	withSystemRoot(t, `C:\Windows`)
	cases := []struct {
		name  string
		in    string
		want  string
		fails bool
	}{
		{"folder", `C:\Games\Steam`, `C:\Games\Steam`, false},
		{"trailing separator", `C:\Games\Steam\`, `C:\Games\Steam`, false},
		{"unc share path", `\\nas\media\games`, `\\nas\media\games`, false},
		{"whole drive", `C:\`, "", true},
		{"whole drive, no separator", `D:`, "", true},
		{"unc share root", `\\nas\media`, "", true},
		{"the system directory", `C:\Windows`, "", true},
		{"inside the system directory", `C:\Windows\System32`, "", true},
		{"a parent of the system directory", `C:\`, "", true},
		{"relative", `Games\Steam`, "", true},
	}
	for _, c := range cases {
		got, err := NormalizeApp(AppFolder, c.in, "")
		if c.fails {
			if err == nil {
				t.Errorf("%s: expected %q to be refused, got %+v", c.name, c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: NormalizeApp(%q) = %v", c.name, c.in, err)
			continue
		}
		if got.Value != c.want {
			t.Errorf("%s: NormalizeApp(%q) = %q, want %q", c.name, c.in, got.Value, c.want)
		}
	}
}

// A two-character title would match nearly every window on the machine, and the
// sweep closes whatever owns a match - so it is refused rather than explained
// afterwards.
func TestNormalizeAppTitleNeedsLength(t *testing.T) {
	if _, err := NormalizeApp(AppTitle, "hi", ""); err == nil {
		t.Error("expected a two-character window title to be refused")
	}
	got, err := NormalizeApp(AppTitle, "  Solitaire  ", "")
	if err != nil {
		t.Fatalf("NormalizeApp: %v", err)
	}
	if got.Value != "Solitaire" {
		t.Errorf("value = %q, want %q", got.Value, "Solitaire")
	}
}

func TestNormalizeAppUnknownKind(t *testing.T) {
	if _, err := NormalizeApp("shortcut", "steam.lnk", ""); err == nil {
		t.Error("expected an unknown kind to be refused")
	}
}

func TestStoreFamily(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		fails bool
	}{
		{"Microsoft.WindowsCalculator_11.2.2.0_x64__8wekyb3d8bbwe", "Microsoft.WindowsCalculator_8wekyb3d8bbwe", false},
		{"Microsoft.WindowsCalculator_8wekyb3d8bbwe", "Microsoft.WindowsCalculator_8wekyb3d8bbwe", false},
		{"Microsoft.WindowsCalculator", "", true},
		{"", "", true},
		{"_8wekyb3d8bbwe", "", true},
	}
	for _, c := range cases {
		got, err := StoreFamily(c.in)
		if c.fails {
			if err == nil {
				t.Errorf("StoreFamily(%q) = %q, want an error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("StoreFamily(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// A Store app runs out of a versioned directory, so the version has to fall away
// for the rule to survive an update - that is the whole reason a store rule
// stores the family name rather than the path.
func TestStoreFamilyFromPath(t *testing.T) {
	const path = `C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2.2.0_x64__8wekyb3d8bbwe\Calculator.exe`
	if got := StoreFamilyFromPath(path); got != "Microsoft.WindowsCalculator_8wekyb3d8bbwe" {
		t.Errorf("StoreFamilyFromPath = %q", got)
	}
	if got := StoreFamilyFromPath(`C:\Games\steam.exe`); got != "" {
		t.Errorf("StoreFamilyFromPath of a normal path = %q, want empty", got)
	}
}

func TestAppMatches(t *testing.T) {
	steam := Process{PID: 100, Name: "steam.exe", Path: `C:\Games\Steam\steam.exe`}
	copied := Process{PID: 101, Name: "steam.exe", Path: `D:\Elsewhere\steam.exe`}
	calc := Process{
		PID:  102,
		Name: "Calculator.exe",
		Path: `C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2.2.0_x64__8wekyb3d8bbwe\Calculator.exe`,
	}
	titled := Process{PID: 103, Name: "game.exe", Titles: []string{"Spider Solitaire - Free"}}

	cases := []struct {
		name string
		app  App
		proc Process
		want bool
	}{
		{"bare name matches any copy", App{Kind: AppExe, Value: "steam.exe"}, copied, true},
		{"bare name is case-insensitive", App{Kind: AppExe, Value: "STEAM.EXE"}, steam, true},
		{"path matches that copy", App{Kind: AppExe, Value: `C:\Games\Steam\steam.exe`}, steam, true},
		{"path does not match another copy", App{Kind: AppExe, Value: `C:\Games\Steam\steam.exe`}, copied, false},
		{"folder matches what is inside it", App{Kind: AppFolder, Value: `C:\Games`}, steam, true},
		{"folder does not match a prefix sibling", App{Kind: AppFolder, Value: `C:\Gam`}, steam, false},
		{"folder does not match another drive", App{Kind: AppFolder, Value: `C:\Games`}, copied, false},
		{"store matches by family", App{Kind: AppStore, Value: "Microsoft.WindowsCalculator_8wekyb3d8bbwe"}, calc, true},
		{"store does not match a normal app", App{Kind: AppStore, Value: "Microsoft.WindowsCalculator_8wekyb3d8bbwe"}, steam, false},
		{"title matches a substring, any case", App{Kind: AppTitle, Value: "solitaire"}, titled, true},
		{"title does not match another window", App{Kind: AppTitle, Value: "minesweeper"}, titled, false},
		{"title does not match a process with no windows", App{Kind: AppTitle, Value: "solitaire"}, steam, false},
	}
	for _, c := range cases {
		if got := c.app.Matches(c.proc); got != c.want {
			t.Errorf("%s: Matches = %v, want %v", c.name, got, c.want)
		}
	}
}

// The guardrail that matters most: no rule, however it got into the config, may
// make the guard terminate something Windows needs - or the guard itself.
func TestBlockedProcessesNeverTouchesProtected(t *testing.T) {
	apps := []App{
		{Kind: AppTitle, Value: "Program Manager"}, // explorer.exe's own window
		{Kind: AppExe, Value: "guard.exe"},         // refused at input, but assume it got in
		{Kind: AppExe, Value: "game.exe"},
	}
	procs := []Process{
		{PID: 4, Name: "System"},
		{PID: 900, Name: "explorer.exe", Titles: []string{"Program Manager"}},
		{PID: 901, Name: "guard.exe", Path: `C:\Program Files\Extension Guard\guard.exe`},
		{PID: 902, Name: "game.exe", Path: `C:\Games\game.exe`},
	}
	got := BlockedProcesses(apps, procs)
	if len(got) != 1 || got[0].PID != 902 {
		t.Fatalf("BlockedProcesses = %+v, want only pid 902", got)
	}
}

func TestNeedsPathsAndTitles(t *testing.T) {
	cases := []struct {
		name       string
		apps       []App
		wantPaths  bool
		wantTitles bool
	}{
		{"bare names only", []App{{Kind: AppExe, Value: "steam.exe"}}, false, false},
		{"a path rule", []App{{Kind: AppExe, Value: `C:\Games\steam.exe`}}, true, false},
		{"a folder rule", []App{{Kind: AppFolder, Value: `C:\Games`}}, true, false},
		{"a store rule", []App{{Kind: AppStore, Value: "A_b"}}, true, false},
		{"a title rule", []App{{Kind: AppTitle, Value: "Solitaire"}}, false, true},
	}
	for _, c := range cases {
		if got := NeedsPaths(c.apps); got != c.wantPaths {
			t.Errorf("%s: NeedsPaths = %v, want %v", c.name, got, c.wantPaths)
		}
		if got := NeedsTitles(c.apps); got != c.wantTitles {
			t.Errorf("%s: NeedsTitles = %v, want %v", c.name, got, c.wantTitles)
		}
	}
}

func TestAddAppIsIdempotentAndReEnables(t *testing.T) {
	var cfg Config
	app, changed, err := cfg.AddApp(AppExe, `C:\Games\steam.exe`, "Steam")
	if err != nil || !changed {
		t.Fatalf("AddApp = %+v, %v, %v", app, changed, err)
	}
	// Same app, written differently: same rule, no change.
	if _, changed, err := cfg.AddApp(AppExe, `c:/games/STEAM.exe`, ""); err != nil || changed {
		t.Errorf("re-adding the same app changed the config (%v, %v)", changed, err)
	}
	if len(cfg.Apps) != 1 {
		t.Fatalf("config has %d apps, want 1", len(cfg.Apps))
	}
	// Switched off, then added again: back on, still one entry.
	if _, ok := cfg.SetAppEnabled(AppExe, `C:\Games\steam.exe`, false); !ok {
		t.Fatal("SetAppEnabled did not find the app")
	}
	if len(cfg.BlockedApps()) != 0 || len(cfg.InactiveApps()) != 1 {
		t.Errorf("after switching off: %d blocked, %d inactive", len(cfg.BlockedApps()), len(cfg.InactiveApps()))
	}
	if _, changed, err := cfg.AddApp(AppExe, `C:\Games\steam.exe`, ""); err != nil || !changed {
		t.Errorf("re-adding a switched-off app should re-enable it (%v, %v)", changed, err)
	}
	if len(cfg.Apps) != 1 || cfg.Apps[0].Disabled {
		t.Errorf("apps = %+v, want one enabled entry", cfg.Apps)
	}
	if cfg.Apps[0].Label != "Steam" {
		t.Errorf("label = %q, want the original label kept", cfg.Apps[0].Label)
	}
}

// Adding an executable that a folder rule already covers tightens nothing, and a
// list with redundant entries is harder to read and slower to sweep.
func TestAddAppRefusesWhatAFolderAlreadyCovers(t *testing.T) {
	withSystemRoot(t, `C:\Windows`)
	var cfg Config
	if _, _, err := cfg.AddApp(AppFolder, `C:\Games\Steam`, ""); err != nil {
		t.Fatalf("AddApp folder: %v", err)
	}
	_, changed, err := cfg.AddApp(AppExe, `C:\Games\Steam\steam.exe`, "")
	if err == nil {
		t.Fatal("expected the covered executable to be refused")
	}
	if changed || len(cfg.Apps) != 1 {
		t.Errorf("refused add still changed the config: %+v", cfg.Apps)
	}
	if !strings.Contains(err.Error(), `C:\Games\Steam`) {
		t.Errorf("error should name the covering folder, got %q", err)
	}
	// A different app in the same folder is a separate rule, not a duplicate.
	if _, _, err := cfg.AddApp(AppExe, `D:\Other\steam.exe`, ""); err != nil {
		t.Errorf("an executable outside the folder should be accepted: %v", err)
	}
}

// The same text can be two different rules. "Steam" as a window title is not
// steam.exe, and unblocking one must not unblock the other.
func TestAppsAreDistinguishedByKind(t *testing.T) {
	var cfg Config
	if _, _, err := cfg.AddApp(AppExe, "steam.exe", ""); err != nil {
		t.Fatalf("AddApp exe: %v", err)
	}
	if _, _, err := cfg.AddApp(AppTitle, "steam.exe", ""); err != nil {
		t.Fatalf("AddApp title: %v", err)
	}
	if len(cfg.Apps) != 2 {
		t.Fatalf("config has %d apps, want 2", len(cfg.Apps))
	}
	if _, ok := cfg.SetAppEnabled(AppTitle, "steam.exe", false); !ok {
		t.Fatal("SetAppEnabled did not find the title rule")
	}
	blocked := cfg.BlockedApps()
	if len(blocked) != 1 || blocked[0].Kind != AppExe {
		t.Errorf("blocked = %+v, want only the exe rule", blocked)
	}
}

func TestValidateAppsRejectsDuplicatesAndJunk(t *testing.T) {
	dup := Config{Apps: []App{
		{Kind: AppExe, Value: `C:\Games\steam.exe`},
		{Kind: AppExe, Value: `c:\games\STEAM.EXE`},
	}}
	if err := dup.Validate(); err == nil {
		t.Error("expected a duplicate app to be reported")
	}
	junk := Config{Apps: []App{{Kind: AppExe, Value: `C:\Games\readme.txt`}}}
	if err := junk.Validate(); err == nil {
		t.Error("expected an unusable app rule to be reported")
	}
}

// A config that blocks only applications has no extensions to recognize its shape
// by; the legacy single-extension fallback must not swallow it.
func TestConfigWithOnlyAppsParses(t *testing.T) {
	var cfg Config
	data := []byte(`{"apps":[{"kind":"exe","value":"steam.exe","label":"Steam"}]}`)
	if err := cfg.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if len(cfg.Apps) != 1 || cfg.Apps[0].Value != "steam.exe" {
		t.Fatalf("apps = %+v", cfg.Apps)
	}
}

// A config with no apps must encode exactly as it did before apps existed, so a
// trusted copy recorded by an older build still compares equal after the upgrade.
func TestAppsOmittedWhenUnused(t *testing.T) {
	cfg := Config{Extensions: []Extension{{Name: "x"}}}
	canon, err := cfg.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if strings.Contains(string(canon), "apps") {
		t.Errorf("canonical encoding mentions apps for a config without any:\n%s", canon)
	}
}

func appScheduleConfig() Config {
	return Config{
		Apps: []App{{Kind: AppExe, Value: "steam.exe"}, {Kind: AppExe, Value: "game.exe"}},
		Blocks: []Block{{
			ID:      "evenings",
			Apps:    []string{"steam.exe"},
			Windows: []Window{{Start: "18:00", End: "22:00"}},
		}},
	}
}

// A scheduled app is enforced during its windows and released outside them, and
// an app no block governs is enforced around the clock. This is the same
// resolution extensions and domains get; apps must not be a special case.
func TestActiveAtResolvesApps(t *testing.T) {
	cfg := appScheduleConfig()
	inside := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	outside := time.Date(2026, 8, 20, 9, 0, 0, 0, time.Local)

	if got := len(cfg.ActiveAt(inside).BlockedApps()); got != 2 {
		t.Errorf("inside the window: %d apps blocked, want 2", got)
	}
	out := cfg.ActiveAt(outside).BlockedApps()
	if len(out) != 1 || out[0].Value != "game.exe" {
		t.Errorf("outside the window: blocked = %+v, want only game.exe", out)
	}
	// The unscheduled app keeps its own state; the schedule does not resurrect an
	// app that was switched off outright.
	cfg.Apps[1].Disabled = true
	if got := len(cfg.ActiveAt(inside).BlockedApps()); got != 1 {
		t.Errorf("with game.exe switched off: %d apps blocked, want 1", got)
	}
}

// The service compares signatures to notice a block boundary without touching the
// registry, so crossing one has to change the signature - otherwise a schedule
// would only take effect on the next 30-second backstop.
func TestActiveSignatureCoversApps(t *testing.T) {
	cfg := appScheduleConfig()
	inside := cfg.ActiveSignature(time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local))
	outside := cfg.ActiveSignature(time.Date(2026, 8, 20, 9, 0, 0, 0, time.Local))
	if inside == outside {
		t.Errorf("signature is unchanged across a block boundary (%q)", inside)
	}
	if !strings.Contains(inside, "steam.exe") {
		t.Errorf("signature does not mention the scheduled app: %q", inside)
	}
}

// A typo in a block's app list would silently govern nothing, which leaves the app
// enforced around the clock while the schedule looks like it applies. Validate
// refuses instead.
func TestValidateRejectsBlockNamingUnknownApp(t *testing.T) {
	cfg := Config{
		Apps:   []App{{Kind: AppExe, Value: "steam.exe"}},
		Blocks: []Block{{ID: "evenings", Apps: []string{"stem.exe"}}},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected a block naming an unknown app to be refused")
	}
	cfg.Blocks[0].Apps = []string{"STEAM.EXE"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("a differently-cased name is the same app: %v", err)
	}
}

// Naming nothing governs everything - including the apps catalog, which is what
// keeps a pre-apps block behaving the way it always did.
func TestBlockNamingNothingGovernsApps(t *testing.T) {
	b := Block{ID: "all"}
	if !b.GovernsApp(App{Kind: AppExe, Value: "steam.exe"}) {
		t.Error("a block naming nothing should govern every app")
	}
	b = Block{ID: "some", Extensions: []string{"sieve"}}
	if b.GovernsApp(App{Kind: AppExe, Value: "steam.exe"}) {
		t.Error("a block naming an extension should not govern apps")
	}
}

// A locked block is immutable except for extending its deadline, and that has to
// include its app list - otherwise swapping the apps out is a way around a
// commitment made specifically because the person did not trust their future self.
func TestCheckLockedBlocksRejectsAppSwap(t *testing.T) {
	now := time.Now()
	locked := Block{
		ID:          "focus",
		Apps:        []string{"steam.exe"},
		LockedUntil: now.Add(48 * time.Hour).Format(time.RFC3339),
	}
	current := Config{Apps: []App{{Kind: AppExe, Value: "steam.exe"}}, Blocks: []Block{locked}}

	swapped := locked
	swapped.Apps = []string{"other.exe"}
	if err := CheckLockedBlocks(current, Config{Blocks: []Block{swapped}}, now); err == nil {
		t.Error("expected swapping a locked block's apps to be refused")
	}

	// Rewriting the same app differently is not a change.
	rewritten := locked
	rewritten.Apps = []string{"STEAM.EXE"}
	if err := CheckLockedBlocks(current, Config{Blocks: []Block{rewritten}}, now); err != nil {
		t.Errorf("re-spelling the same app should not count as a change: %v", err)
	}
}

func TestAppStatusDetail(t *testing.T) {
	a := App{Kind: AppExe, Value: "steam.exe"}
	cases := []struct {
		name         string
		facts        appFacts
		wantEnforced bool
		wantDetail   string
	}{
		{"blocked and quiet", appFacts{present: true, launchApplies: true, launchBlocked: true}, true, "blocked"},
		{"running", appFacts{present: true, running: true, launchApplies: true, launchBlocked: true}, false, "a blocked app is running - closing it"},
		{"launch block gone", appFacts{present: true, launchApplies: true}, false, "launch block missing"},
		{"not installed", appFacts{launchApplies: true, launchBlocked: true}, true, "not on this machine"},
		{"no launch block for this kind", appFacts{present: true}, true, "blocked"},
	}
	for _, c := range cases {
		got := appStatus(a, c.facts)
		if got.Enforced != c.wantEnforced || got.Detail != c.wantDetail {
			t.Errorf("%s: appStatus = {%v, %q}, want {%v, %q}",
				c.name, got.Enforced, got.Detail, c.wantEnforced, c.wantDetail)
		}
	}
}

// The summary is what both the CLI listing and the status window print under a
// rule's name, and it has to say what the rule *covers* - the value alone does
// not distinguish one executable from every copy of it.
func TestAppSummaryAndDisplay(t *testing.T) {
	cases := []struct {
		app  App
		want string
	}{
		{App{Kind: AppFolder, Value: `C:\Games`}, `every .exe in C:\Games`},
		{App{Kind: AppExe, Value: `C:\Games\steam.exe`}, `C:\Games\steam.exe`},
		{App{Kind: AppExe, Value: "steam.exe"}, "steam.exe, wherever it is installed"},
		{App{Kind: AppStore, Value: "A.B_pub"}, "Store app A.B_pub, across updates"},
		{App{Kind: AppTitle, Value: "Solitaire"}, `any window whose title contains "Solitaire"`},
	}
	for _, c := range cases {
		if got := c.app.Summary(); got != c.want {
			t.Errorf("Summary(%+v) = %q, want %q", c.app, got, c.want)
		}
	}
	if got := (App{Kind: AppExe, Value: "steam.exe", Label: "Steam"}).Display(); got != "Steam" {
		t.Errorf("display = %q, want the label", got)
	}
	if got := (App{Kind: AppExe, Value: "steam.exe"}).Display(); got != "steam.exe" {
		t.Errorf("display = %q, want the value when there is no label", got)
	}
}
