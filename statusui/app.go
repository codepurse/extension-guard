// Package main is the status window: a small, unprivileged view of what the
// guard is holding, and the two switches that decide whether that holding means
// anything.
//
// It runs as the person using the machine, not as an administrator. Everything it
// reads, it reads directly; everything it changes, it changes by launching the
// elevated guard and letting Windows ask. That split is deliberate - a window that
// could change enforcement without a prompt would be a window the person being
// restricted could use.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codepurse/extension-guard/internal/activity"
	"github.com/codepurse/extension-guard/internal/auth"
	"github.com/codepurse/extension-guard/internal/buildinfo"
	"github.com/codepurse/extension-guard/internal/guardsvc"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
	"github.com/codepurse/extension-guard/internal/updater"
)

// App is the object Wails binds to the page.
type App struct {
	ctx     context.Context
	cfg     policy.Config
	cfgPath string
}

// Status is everything the window shows, in one round trip.
//
// One call rather than several because the parts have to agree with each other: a
// window that fetched the extensions and then the browsers could show a lock as
// held by a browser the second call found missing, and the reader would have no
// way to tell which half was stale.
type Status struct {
	// Protected is the headline: every enabled extension is locked into every
	// browser that can carry it, the service is running, and nothing is paused.
	// It is what the circle reads.
	Protected bool `json:"protected"`
	// Summary is the sentence under the circle - what is true right now, in the
	// words somebody would use.
	Summary string `json:"summary"`
	// Detail says what is wrong when Protected is false, and is empty when nothing
	// is. A circle that goes amber without saying why is a circle nobody trusts.
	Detail string `json:"detail"`

	ServiceRunning bool   `json:"serviceRunning"`
	Disabled       bool   `json:"disabled"`
	PausedUntil    string `json:"pausedUntil"`
	HasPassword    bool   `json:"hasPassword"`
	Version        string `json:"version"`

	Extensions []ExtensionRow `json:"extensions"`
	Browsers   []BrowserRow   `json:"browsers"`

	// BlockUnsupported is the toggle, and Unmanaged is what it governs: the
	// browsers on this machine that carry none of the locked extensions.
	BlockUnsupported bool           `json:"blockUnsupported"`
	Unmanaged        []UnmanagedRow `json:"unmanaged"`
	// UnmanagedScanned reports whether the machine could be scanned at all. On a
	// machine the guard never looked at, "no browser is unreachable" would be
	// reassurance the window made up.
	UnmanagedScanned bool `json:"unmanagedScanned"`

	// PrivateBrowsing is the other toggle. A force-installed extension does not
	// run in a Chrome, Edge or Brave private window, so without this the lock is
	// one keystroke from being off.
	PrivateBrowsing bool `json:"privateBrowsing"`
	// PrivateBrowsingOpen is that hole, reported whether or not the setting is on.
	PrivateBrowsingOpen bool `json:"privateBrowsingOpen"`
}

// hasTarget reports whether an extension is published for a browser at all. An
// empty target is not a gap - it is an extension that browser has no copy of.
func hasTarget(t policy.Target) bool {
	return strings.TrimSpace(t.ExtensionID) != "" || strings.TrimSpace(t.AddonID) != ""
}

// ExtensionRow is one locked extension and how far the lock reaches.
type ExtensionRow struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
	// Locked is how many browsers hold it, of Total that could.
	Locked int `json:"locked"`
	Total  int `json:"total"`
}

// BrowserRow is one browser the guard writes policy for.
type BrowserRow struct {
	Kind      string `json:"kind"`
	Installed bool   `json:"installed"`
	Locked    bool   `json:"locked"`
	Detail    string `json:"detail"`
}

// UnmanagedRow is one browser the guard cannot reach.
type UnmanagedRow struct {
	Label   string `json:"label"`
	Image   string `json:"image"`
	Blocked bool   `json:"blocked"`
}

// ActionResult is what every change reports back.
type ActionResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// NewApp builds the window's backing object.
func NewApp() *App {
	p := defaultConfigPath()
	cfg, _ := policy.LoadEnforced(p)
	// The window runs unprivileged, so it cannot create the activity log and does
	// not try - it appends to the one the service made. It has to be able to write
	// at all for one reason: a wrong password typed here is verified locally and
	// the elevated guard is never launched, so this is the only place that attempt
	// can be recorded. See internal/activity.
	activity.Enable(activity.LocalUser())
	return &App{cfg: cfg, cfgPath: p}
}

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// GetStatus returns everything the window shows. Read-only and admin-free.
//
// It reloads the config each call, through policy.LoadEnforced: if
// extension-ids.json has been edited by hand the service keeps enforcing the
// trusted copy, and this window has to show what is enforced rather than what the
// file says.
func (a *App) GetStatus() Status {
	if cfg, err := policy.LoadEnforced(a.cfgPath); err == nil {
		a.cfg = cfg
	}

	installed := policy.DetectBrowsers()
	verify := policy.Verify(a.cfg)

	byKind := make(map[policy.Kind]policy.Status, len(verify))
	for _, s := range verify {
		byKind[s.Kind] = s
	}

	browsers := make([]BrowserRow, 0, len(verify))
	lockedBrowsers, presentBrowsers := 0, 0
	for _, s := range verify {
		if s.Installed {
			presentBrowsers++
			if s.Locked {
				lockedBrowsers++
			}
		}
		browsers = append(browsers, BrowserRow{
			Kind:      string(s.Kind),
			Installed: s.Installed,
			Locked:    s.Locked,
			Detail:    s.Detail,
		})
	}

	exts := make([]ExtensionRow, 0, len(a.cfg.Extensions))
	for _, e := range a.cfg.Extensions {
		row := ExtensionRow{
			Name:    e.Name,
			Label:   strings.TrimSpace(e.Label),
			Enabled: !e.Disabled,
		}
		if row.Label == "" {
			row.Label = e.Name
		}
		for _, k := range policy.AllKinds() {
			// A browser only counts when it is here and the extension is published
			// for it. Counting a browser with no store id would report a lock as
			// missing that was never possible.
			if !installed[k] || !hasTarget(e.Target(k)) {
				continue
			}
			row.Total++
			if s, ok := byKind[k]; ok && s.Locked {
				row.Locked++
			}
		}
		exts = append(exts, row)
	}

	unmanaged := make([]UnmanagedRow, 0)
	for _, b := range policy.UnmanagedBrowsers() {
		unmanaged = append(unmanaged, UnmanagedRow{
			Label:   b.Label(),
			Image:   b.Image(),
			Blocked: policy.BrowserBlocked(b.Image()),
		})
	}

	pause := scm.Paused()
	_, hasPw := scm.GetPasswordHash()
	st := Status{
		ServiceRunning:      scm.IsRunning(guardsvc.ServiceName),
		Disabled:            pause.Paused,
		PausedUntil:         pausedUntilLabel(pause),
		HasPassword:         hasPw,
		Version:             buildinfo.Version,
		Extensions:          exts,
		Browsers:            browsers,
		BlockUnsupported:    a.cfg.BlockUnsupported,
		Unmanaged:           unmanaged,
		UnmanagedScanned:    policy.BrowserScanSupported(),
		PrivateBrowsing:     a.cfg.Hardened().PrivateBrowsing,
		PrivateBrowsingOpen: a.cfg.PrivateBrowsingOpen(),
	}
	st.Protected, st.Summary, st.Detail = verdict(st, lockedBrowsers, presentBrowsers)
	return st
}

// verdict turns the state into the one sentence the circle carries.
//
// The order is the order somebody would want to be told. A stopped service beats
// everything, because nothing else is true while it is stopped. A pause beats a
// gap, because the gap is deliberate. A hole in the lock beats a clean bill,
// because a circle that reads "protected" over an open private window is the one
// failure this window exists to prevent.
func verdict(s Status, locked, present int) (bool, string, string) {
	switch {
	case !s.ServiceRunning:
		return false, "Not protected", "The guard service is not running, so nothing is being enforced."
	case s.Disabled:
		detail := "Protection stays off until you turn it back on."
		if s.PausedUntil != "" {
			detail = "Protection turns itself back on at " + s.PausedUntil + "."
		}
		return false, "Paused", detail
	case present == 0:
		return false, "No browser to protect", "None of the browsers the guard manages are installed here."
	case locked < present:
		return false, "Partly protected",
			fmt.Sprintf("%d of %d browsers hold the locked extensions.", locked, present)
	}

	// Locked everywhere it can be - now the two holes beside it.
	var holes []string
	if s.PrivateBrowsingOpen {
		holes = append(holes, "private windows carry none of them")
	}
	loose := 0
	for _, u := range s.Unmanaged {
		if !u.Blocked {
			loose++
		}
	}
	if loose > 0 {
		word := "browser carries"
		if loose > 1 {
			word = "browsers carry"
		}
		holes = append(holes, fmt.Sprintf("%d other %s none of them", loose, word))
	}
	if len(holes) > 0 {
		return false, "Protected, with a way round it",
			"The extensions are locked, but " + strings.Join(holes, ", and ") + "."
	}
	return true, "Protected", ""
}

// SetBlockUnsupported turns the unsupported-browser block on or off.
//
// On only adds protection, so it costs the Windows prompt alone. Off hands back a
// browser carrying none of the locked extensions - a way round every lock at once
// - so it takes the password, which the elevated guard re-checks.
func (a *App) SetBlockUnsupported(on bool, password string) ActionResult {
	if a.cfg.BlockUnsupported == on {
		return ActionResult{OK: true, Message: "Already " + blockedWord(on) + "."}
	}
	args := []string{"-config", a.cfgPath}
	if !on && !scm.IsPaused() {
		pw, bad := passwordArgs(password, "letting unsupported browsers run again")
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
	}
	verb := "unblock-browsers"
	msg := "Unsupported browsers can run again."
	if on {
		verb, msg = "block-browsers", "Unsupported browsers are blocked."
	}
	return a.execGuard(append(args, verb), msg)
}

// SetPrivateBrowsing pins private and guest windows off, or hands them back.
func (a *App) SetPrivateBrowsing(on bool, password string) ActionResult {
	if a.cfg.Hardened().PrivateBrowsing == on {
		return ActionResult{OK: true, Message: "Already " + onOffWord(on) + "."}
	}
	args := []string{"-config", a.cfgPath}
	if !on && !scm.IsPaused() {
		pw, bad := passwordArgs(password, "turning off "+policy.KnobPrivateBrowsing)
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
	}
	verb := "unharden"
	msg := "Private windows work again - and a locked extension does not run in one."
	if on {
		verb, msg = "harden", "Private and guest windows are off."
	}
	return withRestartNote(a.execGuard(append(args, verb, policy.KnobPrivateBrowsing), msg))
}

// NeedsPassword lets the window ask for the password only when the change calls
// for one, rather than prompting every time or - worse - discovering the
// requirement after the Windows prompt has been spent. The answer is not trusted:
// the elevated guard re-checks it.
func (a *App) NeedsPassword(turningOn bool) bool { return !turningOn && !scm.IsPaused() }

// EnableExtension turns an extension back on. Only strengthens, so no password.
func (a *App) EnableExtension(name string) ActionResult {
	return withExtensionRestartNote(a.execGuard(
		[]string{"-config", a.cfgPath, "enable-extension", name},
		"Locked back into every browser that can carry it."))
}

// DisableExtension turns one off, which is the largest single weakening this
// program offers, so it takes the password.
func (a *App) DisableExtension(name, password string) ActionResult {
	args := []string{"-config", a.cfgPath}
	if !scm.IsPaused() {
		pw, bad := passwordArgs(password, "turning an extension off")
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
	}
	return withExtensionRestartNote(a.execGuard(append(args, "disable-extension", name),
		"No longer force-installed. It can be removed from the browser."))
}

// GetVersion is the running build, for the window's footer.
func (a *App) GetVersion() string { return buildinfo.Version }

// CheckForUpdate asks whether there is a newer release. A failure is reported as
// a message rather than swallowed: "could not check" and "you are up to date" are
// different facts and only one of them is reassuring.
func (a *App) CheckForUpdate() UpdateStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rel, err := updater.CheckLatest(ctx)
	if err != nil {
		return UpdateStatus{Current: buildinfo.Version, Error: "Could not check for updates."}
	}
	return UpdateStatus{
		Available: rel.Newer(buildinfo.Version),
		Current:   buildinfo.Version,
		Latest:    rel.Version,
		Notes:     rel.Notes,
	}
}

// UpdateStatus is what a check found.
type UpdateStatus struct {
	Available bool   `json:"available"`
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Notes     string `json:"notes"`
	Error     string `json:"error"`
}

// ApplyUpdate downloads and installs a newer release.
func (a *App) ApplyUpdate() ActionResult {
	return a.execGuard([]string{"-config", a.cfgPath, "update"}, "Updated. The guard restarted itself.")
}

// execGuard runs the guard elevated and waits for it.
//
// Every change the window makes goes through here rather than being done in
// process, and that is the design rather than an inconvenience: this window runs
// as the person being restricted, so it must not be able to change enforcement
// without Windows asking first.
func (a *App) execGuard(args []string, okMsg string) ActionResult {
	guardExe, err := a.guardPath()
	if err != nil {
		return ActionResult{Message: err.Error()}
	}
	code, err := runElevatedAndWait(guardExe, args, false)
	if err != nil {
		if errors.Is(err, errElevationCancelled) {
			return ActionResult{Message: "Cancelled at the Windows permission prompt."}
		}
		return ActionResult{Message: "Could not run the guard: " + err.Error()}
	}
	if code != 0 {
		return ActionResult{Message: fmt.Sprintf("The guard reported an error (exit code %d).", code)}
	}
	// The config it just changed is what the next status read has to see.
	if cfg, err := policy.LoadEnforced(a.cfgPath); err == nil {
		a.cfg = cfg
	}
	return ActionResult{OK: true, Message: okMsg}
}

// guardPath is the guard executable beside this window.
func (a *App) guardPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", errors.New("could not locate this program")
	}
	p := filepath.Join(filepath.Dir(exe), "guard.exe")
	if !fileExists(p) {
		return "", errors.New("guard.exe is not beside this window")
	}
	return p, nil
}

// passwordArgs verifies the password here before spending the Windows prompt on
// a call that would be refused anyway. The elevated guard checks it again: this
// is a courtesy, not the gate.
func passwordArgs(password, what string) ([]string, *ActionResult) {
	hash, ok := scm.GetPasswordHash()
	if !ok {
		return nil, &ActionResult{Message: "No password is set. Install protection first."}
	}
	if !auth.Verify(hash, password) {
		activity.Record(activity.Event{Kind: activity.PasswordFailed, Target: what})
		return nil, &ActionResult{Message: "Incorrect password."}
	}
	return []string{"-password", password}, nil
}

// withRestartNote adds the Firefox caveat when one is open. Mozilla's policy
// engine reads its settings once at startup, so a change made now does not reach
// a running Firefox - and reporting it as applied would be reporting something
// that is not yet true in the browser the person is looking at.
func withRestartNote(res ActionResult) ActionResult {
	if !res.OK {
		return res
	}
	if running := policy.GeckoRunning(); len(running) > 0 {
		res.Message += " " + policy.BrowserNames(running) + " picks this up when it next starts."
	}
	return res
}

// withExtensionRestartNote is the same caveat for an extension change, which
// every browser holds until it restarts - not only the Firefox family. See
// policy.BrowsersRunning.
func withExtensionRestartNote(res ActionResult) ActionResult {
	if !res.OK {
		return res
	}
	if running := policy.BrowsersRunning(); len(running) > 0 {
		names := make([]string, 0, len(running))
		for _, k := range running {
			names = append(names, capitalize(string(k)))
		}
		res.Message += " " + strings.Join(names, ", ") + " picks this up when it next starts."
	}
	return res
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func blockedWord(on bool) string {
	if on {
		return "blocked"
	}
	return "allowed"
}

func onOffWord(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// pausedUntilLabel is when a pause ends, in the words somebody would use, or
// empty for a pause with no deadline.
func pausedUntilLabel(p scm.PauseState) string {
	if !p.Paused || p.Until.IsZero() {
		return ""
	}
	return friendlyTime(p.Until, time.Now())
}

// friendlyTime says when something happens the way a person would: a time today,
// "tomorrow" with the time, otherwise the date.
func friendlyTime(t, now time.Time) string {
	switch calendarDaysBetween(t, now) {
	case 0:
		return t.Format("15:04")
	case 1:
		return "tomorrow at " + t.Format("15:04")
	}
	return t.Format("2 Jan at 15:04")
}

func calendarDaysBetween(t, now time.Time) int {
	a := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	b := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	return int(b.Sub(a).Hours() / 24)
}

// defaultConfigPath finds extension-ids.json beside the executable, then by
// walking up from the working directory - the same order the CLI uses, so the
// window and the command line never disagree about which config they are looking
// at.
func defaultConfigPath() string {
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), "extension-ids.json"); fileExists(p) {
			return p
		}
	}
	if dir, err := os.Getwd(); err == nil {
		for i := 0; i < 6; i++ {
			if p := filepath.Join(dir, "extension-ids.json"); fileExists(p) {
				return p
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "extension-ids.json"
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Disable pauses protection for a while. It weakens everything at once, so it
// takes the password.
func (a *App) Disable(password, pauseFor string) ActionResult {
	args := []string{"-config", a.cfgPath}
	pw, bad := passwordArgs(password, "pausing protection")
	if bad != nil {
		return *bad
	}
	args = append(args, pw...)
	if strings.TrimSpace(pauseFor) != "" {
		args = append(args, "-for", pauseFor)
	}
	return a.execGuard(append(args, "disable"), "Protection is paused.")
}

// Enable ends a pause. Only strengthens, so no password.
func (a *App) Enable() ActionResult {
	return a.execGuard([]string{"-config", a.cfgPath, "enable"}, "Protection is on again.")
}
