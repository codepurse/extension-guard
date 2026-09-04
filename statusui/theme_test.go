package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The stored theme is read before the window exists, by a main() that has no
// way to report a problem and no business refusing to open over one. So every
// shape the file can be in has to resolve to something paintable.
func TestNormalizeThemeFallsBackToDefault(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"light", "light", themeLight},
		{"dark", "dark", themeDark},
		{"system", "system", themeSystem},
		{"cased", "  Dark  ", themeDark},
		{"empty", "", themeDefault},
		{"a value from a newer build", "solarized", themeDefault},
	}
	for _, c := range cases {
		if got := normalizeTheme(c.in); got != c.want {
			t.Errorf("%s: normalizeTheme(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// An explicit choice is the one thing the system setting must not override:
// it is chosen precisely on the machine where the system setting is wrong.
func TestResolveThemeKeepsAnExplicitChoice(t *testing.T) {
	if got := resolveTheme(themeLight); got != themeLight {
		t.Errorf("resolveTheme(light) = %q, want light", got)
	}
	if got := resolveTheme(themeDark); got != themeDark {
		t.Errorf("resolveTheme(dark) = %q, want dark", got)
	}
	// "system" is whatever the desktop says, and both answers are valid here -
	// what matters is that it is one of the two the window can be painted in.
	if got := resolveTheme(themeSystem); got != themeLight && got != themeDark {
		t.Errorf("resolveTheme(system) = %q, want light or dark", got)
	}
}

// A round trip through the real file, in a temporary config directory so the
// test never touches the preference of whoever is running it.
func TestSaveThemeRoundTrips(t *testing.T) {
	dir := t.TempDir()
	// os.UserConfigDir reads APPDATA on Windows and XDG_CONFIG_HOME elsewhere;
	// setting both keeps this test the same on every platform it builds for.
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	if got := loadTheme(); got != themeDefault {
		t.Errorf("loadTheme() with no file = %q, want %q", got, themeDefault)
	}
	if err := saveTheme(themeLight); err != nil {
		t.Fatalf("saveTheme: %v", err)
	}
	if got := loadTheme(); got != themeLight {
		t.Errorf("loadTheme() after saving light = %q, want light", got)
	}

	// A file somebody edited by hand, or one a half-finished write left behind.
	path, err := themePath()
	if err != nil {
		t.Fatalf("themePath: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := loadTheme(); got != themeDefault {
		t.Errorf("loadTheme() on a corrupt file = %q, want %q", got, themeDefault)
	}

	// And the directory it lives in is created rather than assumed.
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Errorf("preference directory missing: %v", err)
	}
}

// The window opens light when nobody has chosen. Asserted rather than left
// implicit because it is a product decision, not an implementation detail:
// Instrument is a paper system, and the app used to follow the desktop.
// Changing it back should mean changing this line on purpose.
func TestDefaultThemeIsLight(t *testing.T) {
	if themeDefault != themeLight {
		t.Errorf("themeDefault = %q, want light", themeDefault)
	}
}

// "Follow the desktop" has to survive a round trip through normalizeTheme.
// It used to fall through the default branch, which was invisible while the
// default was itself system; with the default light, an install that had
// chosen to follow the desktop would have been converted to plain light on
// its next start - silently, and once, so nobody would have reported it.
func TestSystemChoiceSurvivesNormalizing(t *testing.T) {
	if got := normalizeTheme(themeSystem); got != themeSystem {
		t.Errorf("normalizeTheme(system) = %q, want system", got)
	}
	if got := normalizeTheme("  System  "); got != themeSystem {
		t.Errorf("normalizeTheme(padded, cased system) = %q, want system", got)
	}
}

// The window's floor, opening size and ceiling have to stay in that order.
// Six numbers describing one window is exactly where a typo survives review:
// a ceiling under the opening size would open every window already clamped,
// and a floor above it would open one it cannot be shrunk back to.
func TestWindowSizesAreOrdered(t *testing.T) {
	if !(minWidth <= openWidth && openWidth <= maxWidth) {
		t.Errorf("widths out of order: min %d, open %d, max %d", minWidth, openWidth, maxWidth)
	}
	if !(minHeight <= openHeight && openHeight <= maxHeight) {
		t.Errorf("heights out of order: min %d, open %d, max %d", minHeight, openHeight, maxHeight)
	}
	// The floor is a promise that the layout works there: the frontend folds
	// to one column and the tabs to icons at 900px, so a floor below that
	// would allow a size no CSS in the window accounts for.
	if minWidth < 900 {
		t.Errorf("minWidth %d is below the 900px breakpoint the CSS folds at", minWidth)
	}
}
