package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// The window's appearance, and where the choice is kept.
//
// This is the one preference the status window owns. It is deliberately not in
// the guard's config: that file is protected, writing to it needs elevation,
// and asking for a UAC prompt to change a colour would be absurd. It is also
// not only in the webview's localStorage, because main.go has to know the
// answer *before* there is a webview - the window paints its background and
// themes its title bar before the first frame, and both would be the wrong
// colour for the length of a cold start.
const (
	themeSystem = "system"
	themeLight  = "light"
	themeDark   = "dark"

	// themeDefault is what the window opens in when nobody has chosen: light,
	// because Instrument is a paper system. Its grounds are named by role and
	// defined light-first, the ink steps were measured against paper and then
	// re-measured for dark separately, and the app is meant to sit beside the
	// site without a seam. Dark is designed rather than derived, but it is the
	// second set, not the first.
	//
	// This is a change from following the desktop. "System" is still offered
	// and still honoured; it is no longer what an install that has never been
	// asked resolves to, so a machine in dark mode now opens the app light
	// until somebody says otherwise.
	themeDefault = themeLight
)

// uiPrefs is what the file holds. A struct rather than a bare string so a
// second window preference does not need a second file.
type uiPrefs struct {
	Theme string `json:"theme"`
}

// themePath is %AppData%\Extension Guard\ui.json on Windows, and the
// equivalent under the user's config directory elsewhere. Per-user by design:
// two people sharing a PC do not share an eyesight.
//
// The directory keeps the old product name on purpose. The app is called Ward
// now, but this path is where every existing install already wrote its theme:
// rename it and those preferences are silently orphaned - the window reverts to
// the system theme once, for no reason the user can see. It is a private
// directory nobody browses to, so the inconsistency costs nothing and the
// rename would. Same reasoning as the service name and the registry key.
func themePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Extension Guard", "ui.json"), nil
}

// normalizeTheme keeps anything unrecognised - a hand-edited file, a value
// from a newer build - reading as the default rather than failing.
//
// themeSystem needs its own case now. It used to fall through the default
// branch, which was harmless while the default *was* system; with the default
// light, an install that had explicitly chosen "follow the desktop" would have
// been quietly converted to plain light on its next start.
func normalizeTheme(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case themeLight:
		return themeLight
	case themeDark:
		return themeDark
	case themeSystem:
		return themeSystem
	default:
		return themeDefault
	}
}

// loadTheme reads the stored preference. Every failure is the default: a
// missing file is a first run, and an unreadable one is not worth refusing to
// open the window over.
func loadTheme() string {
	path, err := themePath()
	if err != nil {
		return themeDefault
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return themeDefault
	}
	var p uiPrefs
	if err := json.Unmarshal(data, &p); err != nil {
		return themeDefault
	}
	return normalizeTheme(p.Theme)
}

// saveTheme writes the preference, creating the directory on first use.
func saveTheme(theme string) error {
	path, err := themePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(uiPrefs{Theme: normalizeTheme(theme)}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// resolveTheme turns the stored preference into the one of two the window can
// actually be painted in.
func resolveTheme(pref string) string {
	if pref := normalizeTheme(pref); pref != themeSystem {
		return pref
	}
	if systemPrefersLight() {
		return themeLight
	}
	return themeDark
}

// GetTheme reports the stored preference - "system", "light" or "dark" - so
// the window can reconcile the guess it painted with before the backend was
// reachable. Read-only, and needs neither admin nor the password.
func (a *App) GetTheme() string { return loadTheme() }

// SetTheme records the choice and re-themes the window frame to match. The
// page restyles itself; the title bar and the border are the host window's,
// which only the backend can reach.
//
// It returns the theme actually in force, so a caller that asked for "system"
// learns which way that resolved without having to ask the OS itself.
func (a *App) SetTheme(pref string) string {
	pref = normalizeTheme(pref)
	// The write is best-effort on purpose: failing to record the choice costs
	// it at the next start, and refusing to apply it now would cost it twice.
	_ = saveTheme(pref)
	resolved := resolveTheme(pref)
	if a.ctx != nil {
		switch {
		case pref == themeSystem:
			wruntime.WindowSetSystemDefaultTheme(a.ctx)
		case resolved == themeLight:
			wruntime.WindowSetLightTheme(a.ctx)
		default:
			wruntime.WindowSetDarkTheme(a.ctx)
		}
	}
	return resolved
}
