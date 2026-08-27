package policy

import (
	"strings"
	"testing"
)

// withBrowsers points the scan at a fixed machine for the length of a test. The
// real scan reads the registry of whichever machine the tests run on, and a test
// whose result depends on whether the developer happens to have Opera installed
// is not a test.
func withBrowsers(t *testing.T, list ...InstalledBrowser) {
	t.Helper()
	prev := browserScan
	browserScan = func() []InstalledBrowser { return list }
	// The discovered browsers are held for a few seconds (see geckoBrowsers), and
	// a cache filled by the previous test is the machine this one did not
	// describe. Dropped on the way in and on the way out.
	resetGeckoBrowsers()
	t.Cleanup(func() {
		browserScan = prev
		resetGeckoBrowsers()
	})
}

// opera is the ordinary unmanaged browser these tests use, installed where a
// per-user install actually lands - under the user's own profile, which needs no
// administrator and is therefore the install a standard account can perform for
// itself.
func opera() InstalledBrowser {
	return InstalledBrowser{
		Name: "Opera Stable",
		Exe:  `C:\Users\kid\AppData\Local\Programs\Opera\opera.exe`,
	}
}

func chrome() InstalledBrowser {
	return InstalledBrowser{
		Name: "Google Chrome",
		Exe:  `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		Kind: Chrome,
	}
}

// Classification decides whether a browser is a hole or not, so it has to know
// exactly the ones the guard writes policy for and nothing else. A false
// "managed" is the expensive direction: it means the report says the machine is
// covered when it is not.
//
// The Firefox forks in the unmanaged list below are the ones this matters most
// for. Zen reads the policies the guard writes and is classified; LibreWolf and
// Waterfox are the same shape of browser and are not, because where they read
// their policies from has not been checked - see GeckoKinds.
func TestClassifyBrowserRecognizesOnlyWhatTheGuardWritesPolicyFor(t *testing.T) {
	managed := map[string]Kind{
		"chrome.exe":  Chrome,
		"msedge.exe":  Edge,
		"brave.exe":   Brave,
		"firefox.exe": Firefox,
		"zen.exe":     Zen,
	}
	for exe, want := range managed {
		if got := ClassifyBrowser(exe); got != want {
			t.Errorf("ClassifyBrowser(%q) = %q, want %q", exe, got, want)
		}
	}
	for _, exe := range []string{
		"opera.exe", "vivaldi.exe", "librewolf.exe", "waterfox.exe",
		"palemoon.exe", "whale.exe", "browser.exe", "tor.exe", "",
	} {
		if got := ClassifyBrowser(exe); got != "" {
			t.Errorf("ClassifyBrowser(%q) = %q, want unmanaged", exe, got)
		}
	}
}

// A registration gives a full path in whatever case the installer wrote, and
// Windows paths are case-insensitive. Classification that missed a browser
// because of a capital letter would report Chrome itself as a hole.
func TestClassifyBrowserIgnoresCaseAndPath(t *testing.T) {
	for _, exe := range []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\PROGRAM FILES\GOOGLE\CHROME\APPLICATION\CHROME.EXE`,
		"Chrome.Exe",
		`C:/Program Files/Google/Chrome/Application/chrome.exe`,
	} {
		if got := ClassifyBrowser(exe); got != Chrome {
			t.Errorf("ClassifyBrowser(%q) = %q, want %q", exe, got, Chrome)
		}
	}
}

// The registered open command is a command line, not a path, and the shapes it
// comes in are the reason this is parsed rather than read. An unquoted path with
// a space in it is the case that matters: splitting on whitespace hands back
// "C:\Program" and loses the browser entirely, which would read as a machine
// with nothing installed on it.
func TestExeFromCommandPullsThePathOutOfARegisteredCommand(t *testing.T) {
	cases := map[string]string{
		`"C:\Program Files\Opera\opera.exe"`:             `C:\Program Files\Opera\opera.exe`,
		`"C:\Program Files\Opera\opera.exe" -- "%1"`:     `C:\Program Files\Opera\opera.exe`,
		`C:\Program Files\Vivaldi\vivaldi.exe -- "%1"`:   `C:\Program Files\Vivaldi\vivaldi.exe`,
		`C:\Program Files\Vivaldi\vivaldi.exe`:           `C:\Program Files\Vivaldi\vivaldi.exe`,
		`  "C:\tools\whale.exe"  `:                       `C:\tools\whale.exe`,
		`"C:\Program Files\Broken\opera.exe`:             `C:\Program Files\Broken\opera.exe`,
		`C:\NoExtension\something --flag`:                `C:\NoExtension\something`,
		`C:\NoExtension\something`:                       `C:\NoExtension\something`,
		``:                                               ``,
		`"C:\Program Files\Mozilla Firefox\firefox.exe"`: `C:\Program Files\Mozilla Firefox\firefox.exe`,
	}
	for in, want := range cases {
		if got := exeFromCommand(in); got != want {
			t.Errorf("exeFromCommand(%q) = %q, want %q", in, got, want)
		}
	}
}

// BlocksBrowser must agree with the sweep, because the sweep is what actually
// closes the browser. Asking the question through App.Matches rather than by
// comparing strings is what makes that true by construction - so this test is
// really checking that every kind of rule a person might have written to block
// Opera is recognized as blocking Opera.
func TestBlocksBrowserAnswersForEveryKindOfRuleThatWouldCloseIt(t *testing.T) {
	cases := map[string]App{
		"by image name": {Kind: AppExe, Value: "opera.exe"},
		"by full path":  {Kind: AppExe, Value: `C:\Users\kid\AppData\Local\Programs\Opera\opera.exe`},
		"by folder":     {Kind: AppFolder, Value: `C:\Users\kid\AppData\Local\Programs\Opera`},
	}
	for name, rule := range cases {
		cfg := Config{Apps: []App{rule}}
		if !cfg.BlocksBrowser(opera()) {
			t.Errorf("a rule %s does not read as blocking Opera", name)
		}
	}
}

// The rules that must not answer yes. A rule for a different browser is the
// obvious one; a disabled rule is the one worth a test, because a rule the user
// switched off enforces nothing and reporting it as cover would hide a live hole
// behind a rule nobody is applying.
func TestBlocksBrowserIgnoresOtherRulesAndSwitchedOffOnes(t *testing.T) {
	cases := map[string]Config{
		"nothing blocked":     {},
		"a different browser": {Apps: []App{{Kind: AppExe, Value: "vivaldi.exe"}}},
		"an unrelated app":    {Apps: []App{{Kind: AppExe, Value: "steam.exe"}}},
		"a switched-off rule": {Apps: []App{{Kind: AppExe, Value: "opera.exe", Disabled: true}}},
		// A window title cannot be matched against a browser that is not running.
		// It errs towards reporting a gap, which is the safe direction.
		"a window title": {Apps: []App{{Kind: AppTitle, Value: "Opera"}}},
	}
	for name, cfg := range cases {
		if cfg.BlocksBrowser(opera()) {
			t.Errorf("%s reads as blocking Opera", name)
		}
	}
}

// A browser the guard manages is never a finding, however little else is
// configured: the whole point is that the policy reaches inside it.
func TestUnblockedBrowsersIsWhatIsNeitherFilteredNorBlocked(t *testing.T) {
	withBrowsers(t, chrome(), opera(), InstalledBrowser{Name: "Vivaldi", Exe: `C:\Program Files\Vivaldi\vivaldi.exe`})

	cfg := Config{Apps: []App{{Kind: AppExe, Value: "vivaldi.exe"}}}
	open := cfg.UnblockedBrowsers()
	if len(open) != 1 {
		t.Fatalf("got %d unblocked browsers, want 1: %+v", len(open), open)
	}
	if open[0].Label() != "Opera Stable" {
		t.Errorf("unblocked browser is %q, want Opera Stable", open[0].Label())
	}
}

// The finding has to survive a config that blocks the browser only sometimes,
// because that is a real configuration and the answer differs by the hour. The
// caller decides which question it is asking by which config it passes; this
// checks that the two answers actually differ.
func TestUnblockedBrowsersFollowsTheConfigItIsGiven(t *testing.T) {
	withBrowsers(t, opera())

	listed := Config{
		Apps:   []App{{Kind: AppExe, Value: "opera.exe"}},
		Blocks: []Block{{ID: "school", Apps: []string{"opera.exe"}, Windows: []Window{{Start: "09:00", End: "15:00"}}}},
	}
	if len(listed.UnblockedBrowsers()) != 0 {
		t.Error("a browser on the block list reads as unblocked")
	}

	// What the same config resolves to outside the window: the rule is still
	// listed, but nothing is enforcing it, so the browser really is reachable.
	outsideWindow := Config{Apps: []App{{Kind: AppExe, Value: "opera.exe", Disabled: true}}}
	if len(outsideWindow.UnblockedBrowsers()) != 1 {
		t.Error("a browser whose rule is not being enforced reads as blocked")
	}
}

// Every row in the report needs something in its first column. A registration
// with no name is not hypothetical - a half-removed browser leaves one - and a
// blank cell in a warning about protection not applying is the wrong place to
// find out this code did not consider the case.
func TestLabelNeverRendersBlank(t *testing.T) {
	cases := map[string]InstalledBrowser{
		"Opera Stable":  {Name: "Opera Stable", Exe: `C:\x\opera.exe`},
		"opera.exe":     {Exe: `C:\x\opera.exe`},
		"unnamed brows": {},
	}
	for want, b := range cases {
		got := b.Label()
		if got == "" {
			t.Fatalf("%+v has a blank label", b)
		}
		if !strings.HasPrefix(got, want) {
			t.Errorf("%+v labelled %q, want something starting %q", b, got, want)
		}
	}
}

// The unmanaged ones come first because they are the reason the report exists.
// A list that opened with four locked browsers and buried Opera in the middle
// would be technically complete and practically useless.
func TestSortBrowsersPutsTheUnmanagedFirst(t *testing.T) {
	list := []InstalledBrowser{
		chrome(),
		{Name: "Vivaldi", Exe: `C:\x\vivaldi.exe`},
		{Name: "Microsoft Edge", Exe: `C:\y\msedge.exe`, Kind: Edge},
		{Name: "Opera Stable", Exe: `C:\z\opera.exe`},
	}
	sortBrowsers(list)

	want := []string{"Opera Stable", "Vivaldi", "Google Chrome", "Microsoft Edge"}
	for i, w := range want {
		if list[i].Label() != w {
			t.Errorf("position %d is %q, want %q (full order: %v)", i, list[i].Label(), w, labels(list))
		}
	}
}

func labels(list []InstalledBrowser) []string {
	out := make([]string, 0, len(list))
	for _, b := range list {
		out = append(out, b.Label())
	}
	return out
}

// The catastrophic catalog line, and the reason validateCategory checks for it.
// Tor Browser ships its executable as firefox.exe, so "block Tor Browser" is a
// change somebody will one day try to make by adding firefox.exe to the browsers
// category - which would close the machine's real Firefox and take every locked
// extension with it. It must be refused at the source, not caught in review.
func TestNoCategoryMayBlockABrowserTheGuardManages(t *testing.T) {
	for _, exe := range []string{"firefox.exe", "chrome.exe", "msedge.exe", "brave.exe", "CHROME.EXE"} {
		cat := Category{
			ID:    "browsers",
			Label: "Unmanaged browsers",
			Apps:  []App{{Kind: AppExe, Value: exe, Label: "a browser fork"}},
		}
		err := validateCategory("browsers", cat)
		if err == nil {
			t.Errorf("a category naming %q was accepted", exe)
			continue
		}
		if !strings.Contains(err.Error(), "manages") {
			t.Errorf("naming %q was refused for the wrong reason: %v", exe, err)
		}
	}
}

// The shipped browsers category, held to the two claims that make it worth
// having: it names browsers, and it names none of the four that would take the
// filtering down with them. The second is covered generically above; this checks
// the actual shipped data, which is what users get.
func TestTheShippedBrowsersCategoryNamesNoManagedBrowser(t *testing.T) {
	cat, ok := LookupCategory("browsers")
	if !ok {
		t.Fatal("the browsers category is missing from the catalog")
	}
	if len(cat.Apps) == 0 {
		t.Fatal("the browsers category names no applications")
	}
	for _, a := range cat.Apps {
		if k := ClassifyBrowser(a.Value); k != "" {
			t.Errorf("the browsers category names %q, which is the guard's own %s", a.Value, k)
		}
	}
}

// A registration whose executable is gone must not read as reachable. Warning
// that Opera is reachable when the file is not even there would fire on every
// machine that has ever uninstalled a browser, and a warning that is wrong that
// often is one the reader stops seeing.
func TestUnblockedBrowsersIgnoresARegistrationWhoseFileIsGone(t *testing.T) {
	ghost := InstalledBrowser{Name: "Opera Stable", Exe: `C:\gone\opera.exe`, Missing: true}
	withBrowsers(t, ghost)

	var cfg Config
	if got := cfg.UnblockedBrowsers(); len(got) != 0 {
		t.Errorf("a vanished browser reads as reachable: %+v", got)
	}
}

// The rename fingerprint: something was blocked, and the file it named is no
// longer there. This is the one case worth surfacing, and the reason it is gated
// on the browser being blocked is that nothing else distinguishes it from an
// ordinary uninstall.
func TestVanishedBrowsersOnlyReportsWhatWasBlocked(t *testing.T) {
	blocked := InstalledBrowser{Name: "Opera Stable", Exe: `C:\gone\opera.exe`, Missing: true}
	never := InstalledBrowser{Name: "Vivaldi", Exe: `C:\gone\vivaldi.exe`, Missing: true}
	present := InstalledBrowser{Name: "Naver Whale", Exe: `C:\here\whale.exe`}
	withBrowsers(t, blocked, never, present)

	cfg := Config{Apps: []App{
		{Kind: AppExe, Value: "opera.exe"},
		{Kind: AppExe, Value: "whale.exe"},
	}}
	got := cfg.VanishedBrowsers()
	if len(got) != 1 {
		t.Fatalf("got %d vanished browsers, want 1 (only the blocked one): %+v", len(got), got)
	}
	if got[0].Label() != "Opera Stable" {
		t.Errorf("reported %q, want Opera Stable", got[0].Label())
	}
}

// A managed browser is never a finding, even with its file missing: the guard's
// policy is still written and applies again the day it is reinstalled.
func TestVanishedBrowsersIgnoresAManagedBrowser(t *testing.T) {
	gone := chrome()
	gone.Missing = true
	withBrowsers(t, gone)

	cfg := Config{Apps: []App{{Kind: AppExe, Value: "chrome.exe"}}}
	if got := cfg.VanishedBrowsers(); len(got) != 0 {
		t.Errorf("a managed browser was reported as vanished: %+v", got)
	}
}
