package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/codepurse/extension-guard/internal/announce"
	"github.com/codepurse/extension-guard/internal/auth"
	"github.com/codepurse/extension-guard/internal/buildinfo"
	"github.com/codepurse/extension-guard/internal/guardsvc"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
	"github.com/codepurse/extension-guard/internal/updater"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails-bound backend. Its exported methods are callable from the
// frontend as window.go.main.App.<Method>().
type App struct {
	ctx     context.Context
	cfg     policy.Config
	cfgPath string
}

// Status is the snapshot the frontend renders.
type Status struct {
	ServiceRunning bool           `json:"serviceRunning"`
	Disabled       bool           `json:"disabled"`
	LockedCount    int            `json:"lockedCount"`
	HasPassword    bool           `json:"hasPassword"`
	Browsers       []BrowserRow   `json:"browsers"`
	Extensions     []ExtensionRow `json:"extensions"`
	Blocks         []BlockRow     `json:"blocks"`
	Domains        []DomainRow    `json:"domains"`
	Apps           []AppRow       `json:"apps"`
	// ScheduleError is set when the configured schedule does not validate. The
	// guard then enforces everything around the clock and ignores the schedule
	// (policy.EnforcedAt fails closed), so the window must say so rather than
	// show windows that are not actually running.
	ScheduleError string `json:"scheduleError"`
}

// DomainRow is one entry in the site block list. Enabled is the user's own on/off
// choice; Blocked is whether it is actually being filtered at this moment, which
// differs when a schedule has it out of window. Both are shown, because "on but
// not blocking right now" is a state the user needs to be able to tell apart from
// "not working".
type DomainRow struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Blocked   bool   `json:"blocked"`
	Scheduled bool   `json:"scheduled"`
}

// AppRow is one entry in the application block list. Kind and Value identify the
// rule to the guard (both are needed: the same text can be an executable name and
// a window title). Label is what the user reads, Note explains what the rule
// actually covers, and Enabled/Blocked are the same pair as for a domain - the
// user's own choice, and whether it is being enforced at this moment.
type AppRow struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Label     string `json:"label"`
	Note      string `json:"note"`
	Enabled   bool   `json:"enabled"`
	Blocked   bool   `json:"blocked"`
	Scheduled bool   `json:"scheduled"`
}

// BlockRow is one scheduled block as the status window shows it. Schedule and
// Extensions are pre-rendered by policy so the window and the CLI describe a
// block identically.
type BlockRow struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Schedule    string `json:"schedule"`
	Extensions  string `json:"extensions"`
	Active      bool   `json:"active"`
	Locked      bool   `json:"locked"`
	LockedUntil string `json:"lockedUntil"`
}

// ExtensionRow is one manageable extension in the status window. Name is the
// stable id the toggle actions pass to the guard; Label is what the user sees.
type ExtensionRow struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
	// Scheduled means a block governs this extension, so "on" means "on during
	// its windows" rather than around the clock. The window labels it, otherwise
	// an extension idle outside its window looks like a fault.
	Scheduled bool `json:"scheduled"`
}

// ActionResult is what the disable/enable methods report back to the frontend.
type ActionResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// BrowserRow is one row in the status list.
type BrowserRow struct {
	Kind      string `json:"kind"`
	Installed bool   `json:"installed"`
	Locked    bool   `json:"locked"`
	Detail    string `json:"detail"`
}

// NewApp loads the shared config so status reflects the configured extension.
// The resolved path is kept so disable/enable can hand it to the elevated guard.
func NewApp() *App {
	p := defaultConfigPath()
	cfg, _, _ := policy.LoadTrusted(p)
	return &App{cfg: cfg, cfgPath: p}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// GetStatus returns the current protection status. Read-only and admin-free.
// It reloads the config each call so a just-toggled extension is reflected.
//
// The reload goes through policy.LoadTrusted for the same reason the service
// does: if extension-ids.json has been edited by hand, the service keeps
// enforcing the trusted copy, and this window must report that rather than
// repeat the file's claim back to the user. LoadTrusted's repair writes are
// best-effort, so running unprivileged here is fine.
func (a *App) GetStatus() Status {
	if cfg, _, err := policy.LoadTrusted(a.cfgPath); err == nil {
		a.cfg = cfg
	}
	// Verify against the schedule-resolved config, matching what the service
	// actually enforces: outside a block's window its extensions are meant to be
	// absent, and reporting that as "not locked" would read as a fault. The
	// extension rows below deliberately keep using a.cfg instead, because those
	// are the user's own on/off choices - a toggle must not appear to flip itself
	// when a window closes.
	now := time.Now()
	active, _ := a.cfg.EnforcedAt(now)
	verified := policy.Verify(active)
	rows := make([]BrowserRow, 0, len(verified))
	locked := 0
	for _, s := range verified {
		if s.Locked {
			locked++
		}
		rows = append(rows, BrowserRow{
			Kind:      string(s.Kind),
			Installed: s.Installed,
			Locked:    s.Locked,
			Detail:    s.Detail,
		})
	}
	exts := make([]ExtensionRow, 0, len(a.cfg.Extensions))
	for _, e := range a.cfg.Extensions {
		label := e.Label
		if label == "" {
			label = e.Name
		}
		exts = append(exts, ExtensionRow{
			Name:      e.Name,
			Label:     label,
			Enabled:   !e.Disabled,
			Scheduled: a.cfg.GovernedBy(e.Name),
		})
	}

	blocks := make([]BlockRow, 0, len(a.cfg.Blocks))
	for _, b := range a.cfg.Blocks {
		row := BlockRow{
			ID:         b.ID,
			Label:      b.Label,
			Schedule:   b.ScheduleSummary(),
			Extensions: b.GovernedSummary(),
			Active:     b.Active(now),
		}
		if row.Label == "" {
			row.Label = b.ID
		}
		if locked, until := b.LockedAt(now); locked {
			row.Locked = true
			if until.IsZero() {
				row.LockedUntil = "an unreadable date"
			} else {
				row.LockedUntil = until.Local().Format("Mon 2 Jan, 15:04")
			}
		}
		blocks = append(blocks, row)
	}

	blockedNow := make(map[string]bool)
	for _, h := range active.BlockedDomains() {
		blockedNow[h] = true
	}
	domains := make([]DomainRow, 0, len(a.cfg.Domains))
	for _, d := range a.cfg.Domains {
		host, err := policy.NormalizeDomain(d.Name)
		if err != nil {
			host = d.Name // show it as written; Validate explains the problem
		}
		scheduled := false
		for _, b := range a.cfg.Blocks {
			if b.GovernsDomain(host) {
				scheduled = true
				break
			}
		}
		domains = append(domains, DomainRow{
			Name:      host,
			Enabled:   !d.Disabled,
			Blocked:   blockedNow[host],
			Scheduled: scheduled,
		})
	}

	blockedApps := make(map[string]bool)
	for _, app := range active.BlockedApps() {
		blockedApps[appKey(app)] = true
	}
	apps := make([]AppRow, 0, len(a.cfg.Apps))
	for _, raw := range a.cfg.Apps {
		app, err := policy.NormalizeApp(raw.Kind, raw.Value, raw.Label)
		if err != nil {
			// Show it as written and say why it is not doing anything; dropping it
			// would leave the user hunting for a rule they know they added.
			apps = append(apps, AppRow{
				Kind: raw.Kind, Value: raw.Value, Label: raw.Value,
				Note: capitalize(err.Error()), Enabled: !raw.Disabled,
			})
			continue
		}
		apps = append(apps, AppRow{
			Kind:      app.Kind,
			Value:     app.Value,
			Label:     app.Display(),
			Note:      app.Summary(),
			Enabled:   !raw.Disabled,
			Blocked:   blockedApps[appKey(app)],
			Scheduled: a.cfg.GovernedApp(app),
		})
	}

	scheduleErr := ""
	if err := a.cfg.Validate(); err != nil {
		scheduleErr = err.Error()
	}
	_, hasPw := scm.GetPasswordHash()
	return Status{
		ServiceRunning: scm.IsRunning(guardsvc.ServiceName),
		Disabled:       scm.IsDisabled(),
		LockedCount:    locked,
		HasPassword:    hasPw,
		Browsers:       rows,
		Extensions:     exts,
		Blocks:         blocks,
		Domains:        domains,
		Apps:           apps,
		ScheduleError:  scheduleErr,
	}
}

// appKey matches a configured rule to the resolved set. Kind is part of it
// because the same text can be two different rules - "Steam" as a window title is
// not "steam.exe" - and the comparison is case-insensitive because Windows treats
// paths and image names that way.
func appKey(a policy.App) string {
	return strings.ToLower(a.Kind) + "|" + strings.ToLower(a.Value)
}

// BlockDomain adds a site to the block list, covering it and every subdomain.
// Free of the password - it only adds protection, the same gate as enabling an
// extension - but elevated (UAC), because it writes browser policy.
//
// The domain is passed to the guard as typed: normalization, the "already covered
// by a broader entry" check and validation all live in one place there, so the
// window and the CLI accept and refuse exactly the same things.
func (a *App) BlockDomain(name string) ActionResult {
	if strings.TrimSpace(name) == "" {
		return ActionResult{Message: "Type a site to block."}
	}
	if _, err := policy.NormalizeDomain(name); err != nil {
		// Answer an obviously bad entry immediately rather than spending a UAC
		// prompt to be told the same thing.
		return ActionResult{Message: capitalize(err.Error())}
	}
	return a.execGuard(
		[]string{"-config", a.cfgPath, "block-domain", name},
		"Blocked, including every subdomain.")
}

// UnblockDomain stops filtering a site, keeping it in the list so it can be
// turned back on. That weakens protection, so it requires the password - except
// while protection is in the authorized paused state, exactly as for an
// extension.
func (a *App) UnblockDomain(name, password string) ActionResult {
	if strings.TrimSpace(name) == "" {
		return ActionResult{Message: "No site selected."}
	}
	args := []string{"-config", a.cfgPath}
	if !scm.IsDisabled() {
		hash, ok := scm.GetPasswordHash()
		if !ok {
			return ActionResult{Message: "No password is set. Install protection first."}
		}
		if !auth.Verify(hash, password) {
			return ActionResult{Message: "Incorrect password."}
		}
		args = append(args, "-password", password)
	}
	args = append(args, "unblock-domain", name)
	return a.execGuard(args, name+" is no longer filtered.")
}

// BlockApp adds an application to the block list. Free of the password - it only
// adds protection, the same gate as blocking a site - but elevated (UAC), because
// it writes the launch block and the trusted config.
//
// The value is passed to the guard as given: normalization, the guardrail that
// refuses to block part of Windows, and the "already covered by a folder" check
// all live in one place there, so the window and the CLI accept and refuse
// exactly the same things.
func (a *App) BlockApp(kind, value, label string) ActionResult {
	if strings.TrimSpace(value) == "" {
		return ActionResult{Message: "Choose an application to block."}
	}
	if _, err := policy.NormalizeApp(kind, value, label); err != nil {
		// Answer an obviously bad entry immediately rather than spending a UAC
		// prompt to be told the same thing.
		return ActionResult{Message: capitalize(err.Error())}
	}
	args := []string{"-config", a.cfgPath}
	if k := strings.TrimSpace(kind); k != "" {
		args = append(args, "-kind", k)
	}
	if l := strings.TrimSpace(label); l != "" {
		args = append(args, "-label", l)
	}
	args = append(args, "block-app", value)
	return a.execGuard(args, "Blocked. It will be closed if it is running.")
}

// UnblockApp stops enforcing one rule, keeping it in the list so it can be turned
// back on. That weakens protection, so it requires the password - except while
// protection is in the authorized paused state, exactly as for a site.
func (a *App) UnblockApp(kind, value, password string) ActionResult {
	if strings.TrimSpace(value) == "" {
		return ActionResult{Message: "No application selected."}
	}
	args := []string{"-config", a.cfgPath}
	if !scm.IsDisabled() {
		hash, ok := scm.GetPasswordHash()
		if !ok {
			return ActionResult{Message: "No password is set. Install protection first."}
		}
		if !auth.Verify(hash, password) {
			return ActionResult{Message: "Incorrect password."}
		}
		args = append(args, "-password", password)
	}
	if k := strings.TrimSpace(kind); k != "" {
		args = append(args, "-kind", k)
	}
	args = append(args, "unblock-app", value)
	return a.execGuard(args, "It can run again.")
}

// BrowseForExe opens the Windows file picker and returns the chosen executable's
// full path, or "" if the user cancelled. Picking a file changes nothing on its
// own - BlockApp is what applies it - so this needs neither the password nor
// elevation.
func (a *App) BrowseForExe() string {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "Choose the application to block",
		Filters: []wruntime.FileFilter{
			{DisplayName: "Applications (*.exe)", Pattern: "*.exe"},
		},
	})
	if err != nil {
		return ""
	}
	return path
}

// BrowseForFolder opens the folder picker and returns the chosen folder, or "" if
// the user cancelled. Blocking a folder covers every executable in it, which is
// how a game that ships several launchers is blocked once.
func (a *App) BrowseForFolder() string {
	path, err := wruntime.OpenDirectoryDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "Choose a folder - every application in it will be blocked",
	})
	if err != nil {
		return ""
	}
	return path
}

// ListStoreApps lists the Microsoft Store apps installed for this user, for the
// picker. Read-only and admin-free; it reads the per-user package registration
// rather than calling the AppX APIs, so the list opens immediately.
func (a *App) ListStoreApps() []policy.StoreApp {
	return policy.InstalledStoreApps()
}

// capitalize upper-cases the first letter of a Go error string for display.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// BlockDraft is a block as the "New block" form describes it. Days are short
// weekday names ("mon"); From and To are "HH:MM" and both empty means the block is
// always on. Extensions, Domains and Apps are what it governs, by the same
// identifiers the rest of the window uses - naming none of them governs
// everything, which is what the form's "Everything" choice sends.
type BlockDraft struct {
	Label      string   `json:"label"`
	Days       []string `json:"days"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	Extensions []string `json:"extensions"`
	Domains    []string `json:"domains"`
	Apps       []string `json:"apps"`
}

// CreateBlock adds a scheduled block.
//
// This is the one "add" in the window that can need the password, and the reason
// is worth stating plainly: a schedule enforces things only during its windows, so
// putting an extension that was locked around the clock onto a 9-to-5 timetable
// leaves it unenforced for the rest of the day. A block with no windows is always
// on and cannot weaken anything, so that one is free - it is the shape you create
// and then lock. policy.Block.Narrows is the single place that decides which is
// which, and the elevated guard re-checks it, so the gate cannot be skipped from
// here.
func (a *App) CreateBlock(draft BlockDraft, password string) ActionResult {
	if strings.TrimSpace(draft.Label) == "" {
		return ActionResult{Message: "Give the block a name."}
	}
	scheduled := strings.TrimSpace(draft.From) != "" || strings.TrimSpace(draft.To) != ""
	if scheduled && (strings.TrimSpace(draft.From) == "" || strings.TrimSpace(draft.To) == "") {
		return ActionResult{Message: "A window needs both a start and an end time."}
	}

	args := []string{"-config", a.cfgPath}
	if scheduled && !scm.IsDisabled() {
		hash, ok := scm.GetPasswordHash()
		if !ok {
			return ActionResult{Message: "No password is set. Install protection first."}
		}
		if !auth.Verify(hash, password) {
			return ActionResult{Message: "Incorrect password."}
		}
		args = append(args, "-password", password)
	}
	args = append(args, "-label", draft.Label)
	if scheduled {
		args = append(args, "-from", draft.From, "-to", draft.To)
		if len(draft.Days) > 0 {
			args = append(args, "-days", strings.Join(draft.Days, ","))
		}
	}
	// Naming nothing governs every catalog, so the flags are only passed when the
	// form actually chose something.
	for flag, values := range map[string][]string{
		"-extensions": draft.Extensions,
		"-domains":    draft.Domains,
		"-apps":       draft.Apps,
	} {
		if len(values) > 0 {
			args = append(args, flag, strings.Join(values, ","))
		}
	}
	args = append(args, "add-block")

	msg := "Created. It is always on, so you can lock it."
	if scheduled {
		msg = "Created. What it governs is now enforced only during those windows."
	}
	return a.execGuard(args, msg)
}

// RemoveBlock deletes a block. It takes the password even though it usually
// restores around-the-clock enforcement: when two blocks govern the same thing,
// dropping one can narrow the time it is enforced, and deciding which case applies
// is exactly the window-coverage reasoning the guard refuses to do. A locked block
// is refused by the guard itself, password or not.
func (a *App) RemoveBlock(id, password string) ActionResult {
	if strings.TrimSpace(id) == "" {
		return ActionResult{Message: "No block selected."}
	}
	args := []string{"-config", a.cfgPath}
	if !scm.IsDisabled() {
		hash, ok := scm.GetPasswordHash()
		if !ok {
			return ActionResult{Message: "No password is set. Install protection first."}
		}
		if !auth.Verify(hash, password) {
			return ActionResult{Message: "Incorrect password."}
		}
		args = append(args, "-password", password)
	}
	args = append(args, "remove-block", id)
	return a.execGuard(args, "Removed. What it governed is enforced around the clock again.")
}

// LockBlock locks a scheduled block so it cannot be released before the given
// deadline. Free of the password - like enabling an extension it only
// strengthens protection - but still elevated (UAC), because it writes the
// trusted config.
//
// The deadline is passed through to the guard rather than parsed here, so the
// window accepts exactly what the CLI does and there is one place that decides
// what a deadline means.
func (a *App) LockBlock(id, until string) ActionResult {
	if strings.TrimSpace(id) == "" {
		return ActionResult{Message: "No block selected."}
	}
	if strings.TrimSpace(until) == "" {
		return ActionResult{Message: "Choose how long to lock it for."}
	}
	return a.execGuard(
		[]string{"-config", a.cfgPath, "-until", until, "lock", id},
		"Locked. It cannot be released early - not with the password, not by restarting.")
}

// Disable temporarily turns protection off - the one action that *weakens*
// protection, so it requires the uninstall password (verified locally for
// instant feedback, then re-verified by the elevated guard so the gate can't be
// bypassed from the renderer). Enable turns it back on; because that only
// strengthens protection it needs admin (a UAC prompt) but no password.
func (a *App) Disable(password string) ActionResult {
	hash, ok := scm.GetPasswordHash()
	if !ok {
		return ActionResult{Message: "No uninstall password is set. Install protection with the installer (or `guard install-service`) first."}
	}
	if !auth.Verify(hash, password) {
		return ActionResult{Message: "Incorrect password."}
	}
	return a.execGuard([]string{"-config", a.cfgPath, "-password", password, "disable"}, "Protection disabled.")
}

// Enable restores protection. Free (no password) - it only strengthens - but
// still elevated (UAC).
func (a *App) Enable() ActionResult {
	return a.execGuard([]string{"-config", a.cfgPath, "enable"}, "Protection enabled.")
}

// EnableExtension starts locking an extension. Free (no password) since it only
// strengthens protection; still needs admin (UAC).
func (a *App) EnableExtension(name string) ActionResult {
	if name == "" {
		return ActionResult{Message: "No extension selected."}
	}
	return a.execGuard([]string{"-config", a.cfgPath, "enable-extension", name}, name+" is now protected.")
}

// DisableExtension stops locking an extension. That weakens protection, so it
// requires the password - EXCEPT while protection is in the authorized paused
// state (scm.IsDisabled), where there is no active lock to bypass. The check
// keys off the authorized-pause sentinel, not a transient "service not running",
// so a momentary stop can't be exploited to strip extensions without the password.
func (a *App) DisableExtension(name, password string) ActionResult {
	if name == "" {
		return ActionResult{Message: "No extension selected."}
	}
	args := []string{"-config", a.cfgPath}
	if !scm.IsDisabled() {
		hash, ok := scm.GetPasswordHash()
		if !ok {
			return ActionResult{Message: "No password is set. Install protection first."}
		}
		if !auth.Verify(hash, password) {
			return ActionResult{Message: "Incorrect password."}
		}
		args = append(args, "-password", password)
	}
	args = append(args, "disable-extension", name)
	return a.execGuard(args, name+" is no longer locked.")
}

// execGuard runs guard.exe elevated (a UAC prompt), waits, and maps the outcome
// to an ActionResult, returning okMsg on success.
func (a *App) execGuard(args []string, okMsg string) ActionResult {
	guardExe, err := a.guardPath()
	if err != nil {
		return ActionResult{Message: err.Error()}
	}
	code, err := runElevatedAndWait(guardExe, args)
	if err != nil {
		if errors.Is(err, errElevationCancelled) {
			return ActionResult{Message: "Cancelled at the Windows permission prompt."}
		}
		return ActionResult{Message: "Could not run the guard: " + err.Error()}
	}
	if code != 0 {
		return ActionResult{Message: fmt.Sprintf("The guard reported an error (exit code %d).", code)}
	}
	return ActionResult{OK: true, Message: okMsg}
}

// GetVersion returns the running build version, shown in the footer.
func (a *App) GetVersion() string { return buildinfo.Version }

// UpdateStatus is what CheckForUpdate reports to the frontend.
type UpdateStatus struct {
	Available bool   `json:"available"`
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Notes     string `json:"notes"`
	Error     string `json:"error"`
}

// CheckForUpdate asks GitHub whether a newer release exists. Read-only and
// admin-free; the frontend calls it on open and behind a "Check for updates"
// button.
func (a *App) CheckForUpdate() UpdateStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rel, err := updater.CheckLatest(ctx)
	if err != nil {
		return UpdateStatus{Current: buildinfo.Version, Error: "Couldn't check for updates."}
	}
	return UpdateStatus{
		Available: rel.Newer(buildinfo.Version),
		Current:   buildinfo.Version,
		Latest:    rel.Version,
		Notes:     rel.Notes,
	}
}

// ApplyUpdate runs `guard update` elevated (a UAC prompt). Updating only
// strengthens protection, so - like enabling an extension - it needs admin but
// NOT the uninstall password. The elevated guard re-checks GitHub, swaps the
// binaries, and restarts the service.
func (a *App) ApplyUpdate() ActionResult {
	guardExe, err := a.guardPath()
	if err != nil {
		return ActionResult{Message: err.Error()}
	}
	code, err := runElevatedAndWait(guardExe, []string{"-config", a.cfgPath, "update"})
	if err != nil {
		if errors.Is(err, errElevationCancelled) {
			return ActionResult{Message: "Cancelled at the Windows permission prompt."}
		}
		return ActionResult{Message: "Could not run the updater: " + err.Error()}
	}
	if code != 0 {
		return ActionResult{Message: fmt.Sprintf("The updater reported an error (exit code %d).", code)}
	}
	return ActionResult{OK: true, Message: "Update installed. Close and reopen Extension Guard to use the new version."}
}

// GetAnnouncement fetches the remote announcement shown as a dismissible banner.
// Best-effort and read-only; on any error it returns an inactive announcement so
// the frontend simply shows nothing. The frontend remembers dismissed IDs
// locally, so a message is shown once until its ID changes.
func (a *App) GetAnnouncement() announce.Announcement {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ann, err := announce.Fetch(ctx)
	if err != nil {
		return announce.Announcement{} // inactive: show nothing
	}
	return ann
}

// OpenURL opens a link in the user's default browser (used by the announcement
// banner). Restricted to http(s) so a compromised renderer can't ask the shell to
// launch arbitrary schemes or local paths.
func (a *App) OpenURL(url string) {
	if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
		wruntime.BrowserOpenURL(a.ctx, url)
	}
}

// guardPath locates guard.exe next to this status binary, where the installer
// places both.
func (a *App) guardPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	name := "guard"
	if runtime.GOOS == "windows" {
		name = "guard.exe"
	}
	p := filepath.Join(filepath.Dir(exe), name)
	if !fileExists(p) {
		// Name the path. The installer puts both binaries in the same directory, so
		// this only happens to a copy that was moved on its own or run straight out
		// of a build directory - and in both cases the path says which.
		return "", fmt.Errorf("%s was not found next to this app (looked in %s)", name, filepath.Dir(exe))
	}
	return p, nil
}

// defaultConfigPath finds extension-ids.json next to the binary (where the
// installer places a copy) or by walking up from the working directory.
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
	_, err := os.Stat(p)
	return err == nil
}
