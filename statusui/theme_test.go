package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The stored theme is read before the window exists, by a main() that has no
// way to report a problem and no business refusing to open over one. So every
// shape the file can be in has to resolve to something paintable.
func TestNormalizeThemeFallsBackToSystem(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"light", "light", themeLight},
		{"dark", "dark", themeDark},
		{"system", "system", themeSystem},
		{"cased", "  Dark  ", themeDark},
		{"empty", "", themeSystem},
		{"a value from a newer build", "solarized", themeSystem},
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

	if got := loadTheme(); got != themeSystem {
		t.Errorf("loadTheme() with no file = %q, want system", got)
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
	if got := loadTheme(); got != themeSystem {
		t.Errorf("loadTheme() on a corrupt file = %q, want system", got)
	}

	// And the directory it lives in is created rather than assumed.
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Errorf("preference directory missing: %v", err)
	}
}
