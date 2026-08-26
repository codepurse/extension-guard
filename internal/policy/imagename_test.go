package policy

import "testing"

// The bypass this closes, stated as a test: a rule on opera.exe against a process
// running from a file somebody renamed. The name on disk no longer matches; the
// name the author compiled in still does.
func TestABareNameRuleSurvivesARename(t *testing.T) {
	rule := App{Kind: AppExe, Value: "opera.exe"}
	renamed := Process{
		PID:          1234,
		Name:         "chess.exe",
		Path:         `C:\Users\kid\AppData\Local\Programs\Opera\chess.exe`,
		OriginalName: "opera.exe",
	}
	if !rule.Matches(renamed) {
		t.Error("a renamed executable walked out of a bare-name rule")
	}
}

// Renaming must not become a way to match things it should not. The compiled-in
// name is consulted, not trusted as a wildcard: an unrelated program is still
// unrelated however it is named.
func TestTheCompiledInNameDoesNotWidenARule(t *testing.T) {
	rule := App{Kind: AppExe, Value: "opera.exe"}
	cases := map[string]Process{
		"an unrelated program":       {Name: "notepad.exe", Path: `C:\Windows\notepad.exe`, OriginalName: "NOTEPAD.EXE"},
		"no version resource at all": {Name: "chess.exe", Path: `C:\x\chess.exe`},
		"an empty original name":     {Name: "chess.exe", Path: `C:\x\chess.exe`, OriginalName: "   "},
	}
	for name, p := range cases {
		if rule.Matches(p) {
			t.Errorf("%s matched a rule for opera.exe", name)
		}
	}
}

// Case and stray path components in a version resource are not a reason to miss.
// A resource is authored by hand and carries whatever the author typed.
func TestTheCompiledInNameIsMatchedLooselyEnoughToBeUseful(t *testing.T) {
	rule := App{Kind: AppExe, Value: "opera.exe"}
	for _, orig := range []string{"OPERA.EXE", "Opera.Exe", ` opera.exe `, `src\opera.exe`} {
		p := Process{Name: "chess.exe", Path: `C:\x\chess.exe`, OriginalName: orig}
		if !rule.Matches(p) {
			t.Errorf("OriginalName %q did not match a rule for opera.exe", orig)
		}
	}
}

// A full-path rule means that copy of that file. Renaming makes it a different
// path, and quietly treating it as the same one would widen a rule the user
// deliberately narrowed - the bare-name form is how you say "wherever it is".
func TestAFullPathRuleIsNotWidenedByTheCompiledInName(t *testing.T) {
	rule := App{Kind: AppExe, Value: `C:\Program Files\Opera\opera.exe`}
	renamed := Process{
		Name:         "chess.exe",
		Path:         `C:\Program Files\Opera\chess.exe`,
		OriginalName: "opera.exe",
	}
	if rule.Matches(renamed) {
		t.Error("a full-path rule matched a different path because of a version resource")
	}
}

// The guardrail has to cover the new name too. A rule that can now fire on a
// version resource must be refusable on one, or the protected list would guard one
// of the two ways to reach lsass.exe and not the other.
func TestTheProtectedListCoversTheCompiledInName(t *testing.T) {
	// A rule somebody got into the config for a name that is not protected, against
	// a process that is - a system binary copied and renamed, which is a real way
	// to try to get the guard to shoot the machine.
	rule := App{Kind: AppExe, Value: "harmless.exe"}
	// "lsass.exe.mui" as well as the tidy form, because the MUI shape is what
	// Windows actually reports for its own binaries - their strings live in a
	// side-by-side resource file. A test using only "lsass.exe" would pass while
	// the guardrail recognized nothing at all on a real machine.
	for _, orig := range []string{"lsass.exe", "LSASS.EXE.MUI", "lsass.exe.mui"} {
		disguised := Process{
			PID:          900,
			Name:         "harmless.exe",
			Path:         `C:\Users\kid\harmless.exe`,
			OriginalName: orig,
		}
		if got := BlockedProcesses([]App{rule}, []Process{disguised}); len(got) != 0 {
			t.Errorf("OriginalName %q: the sweep would terminate a process whose real image is lsass.exe", orig)
		}
	}
}

// The MUI reduction itself, which is the whole difference between the protected
// list covering Windows' own binaries and covering none of them.
func TestOriginalImageStripsTheMUISuffix(t *testing.T) {
	cases := map[string]string{
		"NOTEPAD.EXE.MUI": "NOTEPAD.EXE",
		"Cmd.Exe.MUI":     "Cmd.Exe",
		"lsass.exe.mui":   "lsass.exe",
		"chrome.exe":      "chrome.exe",
		"":                "",
		// Not an executable underneath, so the suffix stays. This must not become a
		// rule that rewrites every name ending in .mui.
		"strings.mui": "strings.mui",
		// A path inside the resource is reduced to its file name, as everywhere else.
		`src\opera.exe`: "opera.exe",
	}
	for in, want := range cases {
		if got := (Process{OriginalName: in}).OriginalImage(); got != want {
			t.Errorf("OriginalImage(%q) = %q, want %q", in, got, want)
		}
	}
}

// And the ordinary case still works: a protected name reached the config somehow,
// and the sweep refuses it on the name on disk exactly as it always did.
func TestTheProtectedListStillCoversTheNameOnDisk(t *testing.T) {
	rule := App{Kind: AppExe, Value: "explorer.exe"}
	p := Process{PID: 900, Name: "explorer.exe", Path: `C:\Windows\explorer.exe`}
	if got := BlockedProcesses([]App{rule}, []Process{p}); len(got) != 0 {
		t.Errorf("the sweep would terminate explorer.exe: %+v", got)
	}
}

// Only a bare-name rule can be defeated by a rename, so only a bare-name rule
// pays for reading version resources. Everything else must not ask.
func TestNeedsOriginalNamesAsksOnlyForBareNameRules(t *testing.T) {
	wants := map[string][]App{
		"a bare name":              {{Kind: AppExe, Value: "steam.exe"}},
		"a bare name with no kind": {{Value: "steam.exe"}},
	}
	for name, apps := range wants {
		if !NeedsOriginalNames(apps) {
			t.Errorf("%s did not ask for compiled-in names", name)
		}
	}

	skips := map[string][]App{
		"a full path":     {{Kind: AppExe, Value: `C:\Games\Steam\steam.exe`}},
		"a folder":        {{Kind: AppFolder, Value: `C:\Games\Steam`}},
		"a Store package": {{Kind: AppStore, Value: "Microsoft.GamingApp_8wekyb3d8bbwe"}},
		"a window title":  {{Kind: AppTitle, Value: "Solitaire"}},
		"nothing at all":  nil,
	}
	for name, apps := range skips {
		if NeedsOriginalNames(apps) {
			t.Errorf("%s asked for compiled-in names, which cannot help it", name)
		}
	}
}

// Reading a version resource means reading the file, which means knowing where it
// is. A snapshot that asked for compiled-in names without paths would silently
// gather nothing, which is the shape of bug that makes a rule look enforced and
// enforce nothing.
func TestAskingForCompiledInNamesImpliesAskingForPaths(t *testing.T) {
	needs := SnapshotNeedsFor([]App{{Kind: AppExe, Value: "steam.exe"}})
	if !needs.Originals {
		t.Fatal("a bare-name rule did not ask for compiled-in names")
	}
	if !needs.WantPaths() {
		t.Error("compiled-in names were requested without the paths needed to read them")
	}
	// Paths itself stays false: nothing here is matched on a path, and the flag
	// says what the rules need rather than what the reader needs.
	if needs.Paths {
		t.Error("a bare-name rule claimed to be matched on paths")
	}

	empty := SnapshotNeedsFor(nil)
	if empty.WantPaths() || empty.Titles || empty.Originals {
		t.Errorf("no rules asked for something: %+v", empty)
	}
}

func TestSnapshotNeedsOrCombinesEveryField(t *testing.T) {
	a := SnapshotNeeds{Paths: true}
	b := SnapshotNeeds{Titles: true}
	c := SnapshotNeeds{Originals: true}
	got := a.Or(b).Or(c)
	if !got.Paths || !got.Titles || !got.Originals {
		t.Errorf("Or lost a field: %+v", got)
	}
}
