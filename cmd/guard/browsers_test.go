package main

import (
	"strings"
	"testing"

	"github.com/codepurse/extension-guard/internal/policy"
)

func zen() policy.InstalledBrowser {
	return policy.InstalledBrowser{Name: "Zen Browser", Exe: `C:\Program Files\Zen Browser\zen.exe`}
}

func operaBrowser() policy.InstalledBrowser {
	return policy.InstalledBrowser{Name: "Opera Stable", Exe: `C:\Users\kid\Opera\opera.exe`}
}

// The warning `guard verify` prints is the only line contradicting a table that
// otherwise says every browser is locked, so it has to read as a sentence someone
// wrote on purpose. "1 browsers are" reads as a bug, and a warning that reads as a
// bug is one the reader learns to skip.
func TestBrowserWarningReadsAsEnglishForOneAndForSeveral(t *testing.T) {
	one := browserWarningFor([]policy.InstalledBrowser{zen()}, nil)
	if !strings.Contains(one, "1 browser on this machine") {
		t.Errorf("singular warning is not singular: %q", one)
	}
	if strings.Contains(one, "1 browsers") || strings.Contains(one, "through them") {
		t.Errorf("singular warning uses plural wording: %q", one)
	}
	if !strings.Contains(one, "Zen Browser") {
		t.Errorf("singular warning does not name the browser: %q", one)
	}

	two := browserWarningFor([]policy.InstalledBrowser{zen(), operaBrowser()}, nil)
	if !strings.Contains(two, "2 browsers on this machine") {
		t.Errorf("plural warning is not plural: %q", two)
	}
	if !strings.Contains(two, "through them") {
		t.Errorf("plural warning uses the singular pronoun: %q", two)
	}
	for _, want := range []string{"Zen Browser", "Opera Stable"} {
		if !strings.Contains(two, want) {
			t.Errorf("plural warning does not name %q: %q", want, two)
		}
	}
}

// The vanished-executable warning is the rename detector's only voice, so it has
// to say both of the things that could have happened rather than accusing anyone.
// It also has to conjugate: "1 browser were on the block list" is the same class
// of tell as the plural bug above.
func TestVanishedWarningNamesBothExplanations(t *testing.T) {
	one := browserWarningFor(nil, []policy.InstalledBrowser{operaBrowser()})
	if !strings.Contains(one, "1 browser") || !strings.Contains(one, "the executable it named is gone") {
		t.Errorf("singular vanished warning reads wrong: %q", one)
	}
	if !strings.Contains(one, "uninstalled") || !strings.Contains(one, "renamed") {
		t.Errorf("vanished warning does not offer both explanations: %q", one)
	}
	if !strings.Contains(one, "Opera Stable") {
		t.Errorf("vanished warning does not name the browser: %q", one)
	}

	two := browserWarningFor(nil, []policy.InstalledBrowser{operaBrowser(), zen()})
	if !strings.Contains(two, "2 browsers") || !strings.Contains(two, "the executables they named are gone") {
		t.Errorf("plural vanished warning reads wrong: %q", two)
	}
}

// Both findings at once is a real state - one browser reachable, another blocked
// and vanished - and they are separate paragraphs because they call for different
// things. One run-on line would read as a single confused complaint.
func TestBothWarningsAppearSeparatelyWhenBothApply(t *testing.T) {
	got := browserWarningFor([]policy.InstalledBrowser{zen()}, []policy.InstalledBrowser{operaBrowser()})
	if !strings.Contains(got, "is not blocking") {
		t.Errorf("the reachable warning is missing: %q", got)
	}
	if !strings.Contains(got, "is gone") {
		t.Errorf("the vanished warning is missing: %q", got)
	}
	if !strings.Contains(got, "\n\n") {
		t.Errorf("the two warnings are not separated: %q", got)
	}
}

// Nothing to warn about must produce nothing at all, not an empty warning with a
// blank list after the colon. printStatus tests the string rather than the count,
// so a warning that is technically non-empty would be printed.
func TestBrowserWarningIsSilentWhenThereIsNothingToSay(t *testing.T) {
	if got := browserWarningFor(nil, nil); got != "" {
		t.Errorf("warned about nothing: %q", got)
	}
	if got := browserWarningFor([]policy.InstalledBrowser{}, []policy.InstalledBrowser{}); got != "" {
		t.Errorf("warned about two empty lists: %q", got)
	}
}

// A registration with no readable name still has to appear in the warning, since
// an unnamed browser is exactly as much of a hole as a named one. Label already
// guarantees a non-blank string; this checks the warning actually uses it rather
// than printing the empty Name field.
func TestBrowserWarningNamesABrowserWithNoRegisteredName(t *testing.T) {
	got := browserWarningFor([]policy.InstalledBrowser{{Exe: `C:\portable\vivaldi.exe`}}, nil)
	if !strings.Contains(got, "vivaldi.exe") {
		t.Errorf("warning does not fall back to the executable name: %q", got)
	}
	if strings.HasSuffix(strings.SplitN(got, "\n", 2)[0], ": ") {
		t.Errorf("warning has a blank name after the colon: %q", got)
	}
}

func TestTruncateKeepsANameInsideItsColumn(t *testing.T) {
	if got := truncate("Opera", 34); got != "Opera" {
		t.Errorf("truncate shortened a name that fits: %q", got)
	}
	long := strings.Repeat("x", 40)
	got := truncate(long, 34)
	if len([]rune(got)) != 34 {
		t.Errorf("truncate(%d chars, 34) produced %d runes", len(long), len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("a truncated name does not say it was cut: %q", got)
	}
	// A non-ASCII name must not be cut mid-character. Maxthon registers itself in
	// Chinese on a Chinese install.
	cjk := strings.Repeat("浏", 40)
	if cut := truncate(cjk, 10); len([]rune(cut)) != 10 || !strings.HasSuffix(cut, "…") {
		t.Errorf("truncate mangled a non-ASCII name: %q", cut)
	}
}
