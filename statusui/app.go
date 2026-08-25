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

	"github.com/codepurse/extension-guard/internal/activity"
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
	ServiceRunning bool `json:"serviceRunning"`
	// Disabled is whether protection is paused. It keeps its name because that is
	// what the frontend has always called it; PausedUntil says when it lifts, and
	// is empty for a pause with no deadline. The two together are what let the
	// window say "back on at 15:04" instead of leaving the user to remember.
	Disabled    bool           `json:"disabled"`
	PausedUntil string         `json:"pausedUntil"`
	LockedCount int            `json:"lockedCount"`
	HasPassword bool           `json:"hasPassword"`
	Browsers    []BrowserRow   `json:"browsers"`
	Extensions  []ExtensionRow `json:"extensions"`
	Blocks      []BlockRow     `json:"blocks"`
	Domains     []DomainRow    `json:"domains"`
	Apps        []AppRow       `json:"apps"`
	// UsageError is set when the daily-limit counters could not be read. Every
	// limit then counts as used up (policy.Spent fails closed), which looks like a
	// fault from the outside unless the window says what happened.
	UsageError string `json:"usageError"`
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
	ID         string `json:"id"`
	Label      string `json:"label"`
	Schedule   string `json:"schedule"`
	Extensions string `json:"extensions"`
	Active     bool   `json:"active"`
	// Limit is the daily budget ("45m/day"), empty for a block without one. Used
	// and Left are today's spend and what remains, already rendered - the window
	// and the CLI describe a limit in the same words because policy formats both.
	//
	// InBudget is the state that only a limited block can be in: on, in window, and
	// not enforcing anything because there is time left. It is separate from Active
	// so the row can say "42m left today" instead of "Idle", which would read as a
	// fault in precisely the case the user is checking on.
	Limit       string `json:"limit"`
	Used        string `json:"used"`
	Left        string `json:"left"`
	InBudget    bool   `json:"inBudget"`
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
	// The window runs unprivileged, so it cannot create the activity log and does
	// not try - it appends to the one the service made. It has to be able to write
	// at all for one reason: a wrong password typed here is verified locally and
	// the elevated guard is never launched, so this is the only place that attempt
	// can be recorded. See internal/activity.
	activity.Enable(activity.LocalUser())
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
	// Read the day's usage once and hand it to everything below, so the block rows,
	// the app rows and the resolved config all agree about a budget that may run out
	// while this function is running.
	spent := a.cfg.SpentAt(now)
	active, _ := a.cfg.EnforcedAtWith(now, spent)
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
			Active:     b.EnforcingAt(now, spent),
			Limit:      b.LimitSummary(),
		}
		if b.HasLimit() && !spent.Unreadable {
			row.Used = policy.HumanDuration(spent.On(b.ID))
			row.Left = policy.HumanDuration(b.Remaining(spent))
			row.InBudget = !row.Active && b.InWindow(now)
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
	usageErr := ""
	if spent.Unreadable {
		usageErr = "The record of today's usage could not be read, so every daily limit counts as used up. " +
			"The guard rewrites it from its own running count within half a minute; if it has to be restarted " +
			"first, today's counts start again from zero and the activity list says so."
	}
	_, hasPw := scm.GetPasswordHash()
	pause := scm.Paused()
	return Status{
		ServiceRunning: scm.IsRunning(guardsvc.ServiceName),
		Disabled:       pause.Paused,
		PausedUntil:    pausedUntilLabel(pause),
		LockedCount:    locked,
		HasPassword:    hasPw,
		Browsers:       rows,
		Extensions:     exts,
		Blocks:         blocks,
		Domains:        domains,
		Apps:           apps,
		UsageError:     usageErr,
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
		withFirefoxNote("Blocked, including every subdomain."))
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
	if !scm.IsPaused() {
		pw, bad := passwordArgs(password, "unblocking a site")
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
	}
	args = append(args, "unblock-domain", name)
	return a.execGuard(args, withFirefoxNote(name+" is no longer filtered."))
}

// withFirefoxNote adds the one caveat a site block still has. Chrome, Edge and
// Brave are made to re-read their policy as part of applying the change, so they
// honour it within a second or two - but Firefox reads its policies only when it
// starts and offers no way to reload them, so a change made while Firefox is open
// does not reach it until it is restarted. Saying so only when Firefox is actually
// running keeps the message off the machines it does not apply to.
func withFirefoxNote(msg string) string {
	if !policy.FirefoxRunning() {
		return msg
	}
	return msg + " Firefox applies this the next time it starts."
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
	if !scm.IsPaused() {
		pw, bad := passwordArgs(password, "unblocking an application")
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
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
	Label string   `json:"label"`
	Days  []string `json:"days"`
	From  string   `json:"from"`
	To    string   `json:"to"`
	// Limit is a daily time budget as the form collects it: "45m", "1h30m", or a
	// number of minutes. Empty means no limit. It may only cover applications, and
	// the guard refuses it otherwise - see policy.Config.validateLimits.
	Limit      string   `json:"limit"`
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
	limit := strings.TrimSpace(draft.Limit)
	if limit != "" {
		// Answer both of these here rather than spending a UAC prompt and a password
		// to be told the same thing. The guard re-checks both - it has to, since the
		// window is not the only way in - but being refused after typing a password
		// is a worse experience than being refused before.
		if _, err := policy.ParseLimit(limit); err != nil {
			return ActionResult{Message: capitalize(err.Error())}
		}
		if len(draft.Apps) == 0 {
			return ActionResult{Message: "A time limit has to cover applications: the guard measures use by watching " +
				"programs run, and a browser never reports back how long a site was open."}
		}
		if len(draft.Extensions) > 0 || len(draft.Domains) > 0 {
			return ActionResult{Message: "A time limit can only cover applications, not extensions or sites."}
		}
	}

	// A limit narrows enforcement exactly as a window does - an application that was
	// blocked outright becomes one you may use for forty-five minutes - so it is
	// gated the same way. policy.Block.Narrows is the one place that decides.
	narrows := scheduled || limit != ""

	args := []string{"-config", a.cfgPath}
	if narrows && !scm.IsPaused() {
		reason := "putting protection on a schedule"
		if !scheduled {
			reason = "allowing a daily amount of time"
		}
		pw, bad := passwordArgs(password, reason)
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
	}
	args = append(args, "-label", draft.Label)
	if scheduled {
		args = append(args, "-from", draft.From, "-to", draft.To)
		if len(draft.Days) > 0 {
			args = append(args, "-days", strings.Join(draft.Days, ","))
		}
	}
	if limit != "" {
		args = append(args, "-limit", limit)
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
	switch {
	case limit != "":
		msg = "Created. That much is allowed each day, and it is blocked once the time is used up."
	case scheduled:
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
	if !scm.IsPaused() {
		pw, bad := passwordArgs(password, "removing a scheduled block")
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
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
// A locked block refuses the pause outright, before the password is even looked
// at - a lock is the one promise the password is not supposed to override, and a
// pause would lift everything it holds. See policy.CheckPausable. The elevated
// guard checks this again, so answering here is a courtesy rather than the gate:
// it saves a UAC prompt spent to be told the same thing, the way BlockDomain
// answers an unusable site immediately.
//
// The config is re-read rather than trusted from the last GetStatus, because a
// stale copy could refuse a pause that is actually allowed, and being told no
// when the answer is yes is the one failure mode here with no recourse.
// pauseFor is how long the pause lasts - "30m", "2h", "1d", or a time - and an
// empty string pauses until somebody turns protection back on. It is passed
// through to the guard rather than parsed here, so the window accepts exactly
// what the CLI does and one place decides what a duration means.
func (a *App) Disable(password, pauseFor string) ActionResult {
	cfg := a.cfg
	if fresh, _, err := policy.LoadTrusted(a.cfgPath); err == nil {
		cfg = fresh
	}
	if err := policy.CheckPausable(cfg, time.Now()); err != nil {
		// Recorded here because it is recorded nowhere else: this refusal never
		// reaches the elevated guard, so without this the attempt leaves no trace.
		activity.Record(activity.Event{Kind: activity.PauseRefused, Detail: err.Error()})
		return ActionResult{Message: capitalize(err.Error()) +
			". Uninstalling still works, and takes the blocks with it."}
	}
	hash, ok := scm.GetPasswordHash()
	if !ok {
		return ActionResult{Message: "No uninstall password is set. Install protection with the installer (or `guard install-service`) first."}
	}
	if !auth.Verify(hash, password) {
		activity.Record(activity.Event{Kind: activity.PasswordFailed, Target: "pausing protection"})
		return ActionResult{Message: "Incorrect password."}
	}
	args := []string{"-config", a.cfgPath, "-password", password}
	msg := "Protection paused until you turn it back on."
	if d := strings.TrimSpace(pauseFor); d != "" {
		args = append(args, "-for", d)
		msg = "Protection paused. It turns itself back on when the time is up."
	}
	args = append(args, "disable")
	return a.execGuard(args, msg)
}

// Enable restores protection. Free (no password) - it only strengthens - but
// still elevated (UAC).
func (a *App) Enable() ActionResult {
	return a.execGuard([]string{"-config", a.cfgPath, "enable"}, "Protection enabled.")
}

// PauseChoice is one option in the window's pause menu. Spec is what gets passed
// to the guard as -for; an empty Spec is the indefinite pause.
type PauseChoice struct {
	Label string `json:"label"`
	Spec  string `json:"spec"`
}

// PauseChoices are the durations the window offers.
//
// A bounded pause is listed first and an indefinite one last, deliberately. An
// indefinite pause is the one that goes wrong by accident - somebody turns
// protection off to sort something out and never turns it back on - and it is the
// only option here that needs a person to remember anything.
func (a *App) PauseChoices() []PauseChoice {
	return []PauseChoice{
		{Label: "15 minutes", Spec: "15m"},
		{Label: "1 hour", Spec: "1h"},
		{Label: "4 hours", Spec: "4h"},
		{Label: "Until tomorrow", Spec: "1d"},
		{Label: "Until I turn it back on", Spec: ""},
	}
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
	if !scm.IsPaused() {
		pw, bad := passwordArgs(password, "turning an extension off")
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
	}
	args = append(args, "disable-extension", name)
	return a.execGuard(args, name+" is no longer locked.")
}

// passwordArgs verifies the uninstall password for an action that weakens
// protection and returns the flag pair to hand to the elevated guard. The
// returned result is nil when the password checked out; otherwise it is what the
// caller should return.
//
// It exists so every such action gates and records identically. The window is
// where a failed attempt has to be recorded: it verifies locally for instant
// feedback and never launches the guard when the password is wrong, so nothing
// further down the chain ever learns the attempt happened. what names the action
// in the record.
//
// The elevated guard re-verifies the password itself, so this staying in the
// renderer is a convenience, not the gate.
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

// ActivityRow is one entry in the Recent activity list.
//
// When and Text are pre-rendered here rather than in the frontend, for the same
// reason policy renders a block's schedule summary: the window and
// `guard activity` should describe the same event in the same words. Severity is
// what the row is coloured by - see activity.Severity* - so the list separates
// "protection did its job" from "protection was weakened" at a glance, which is
// the distinction someone scanning it actually cares about.
type ActivityRow struct {
	When     string `json:"when"`
	Text     string `json:"text"`
	Detail   string `json:"detail"`
	Actor    string `json:"actor"`
	Severity string `json:"severity"`
}

// How many entries the list shows. defaultActivityRows is what the window asks
// for on open; maxActivityRows caps what it can ask for, so a frontend bug cannot
// turn one call into a walk over the whole log.
const (
	defaultActivityRows = 12
	maxActivityRows     = 200
)

// GetActivity returns the recent activity entries, newest first.
//
// Read-only and admin-free, deliberately: the record is meant to be readable by
// everyone it is about, and needing elevation to see it would make that
// transparency theoretical.
func (a *App) GetActivity(limit int) []ActivityRow {
	if limit <= 0 {
		limit = defaultActivityRows
	}
	if limit > maxActivityRows {
		limit = maxActivityRows
	}
	events := activity.Recent(limit)
	now := time.Now()
	rows := make([]ActivityRow, 0, len(events))
	for _, ev := range events {
		rows = append(rows, ActivityRow{
			When:     friendlyTime(ev.Time.Local(), now),
			Text:     activity.Describe(ev),
			Detail:   ev.Detail,
			Actor:    ev.Actor,
			Severity: ev.Severity(),
		})
	}
	return rows
}

// ActivityPath is where the full record is kept, shown under the list. A parent
// who wants to keep or read the raw record should not have to be told where to
// look.
func (a *App) ActivityPath() string { return activity.Path() }

// friendlyTime renders a timestamp the way someone reading a list of recent
// events wants it: the time alone for today, the weekday within the last week,
// and a date once it is older than that. An absolute date on every row would
// make "this morning" and "last month" look alike at a glance, which is the one
// distinction the list is scanned for.
func friendlyTime(t, now time.Time) string {
	switch days := calendarDaysBetween(t, now); {
	case days <= 0:
		return t.Format("15:04")
	case days == 1:
		return "Yesterday " + t.Format("15:04")
	case days < 7:
		return t.Format("Mon 15:04")
	default:
		return t.Format("2 Jan 15:04")
	}
}

// calendarDaysBetween counts whole days from t's calendar date to now's.
//
// It compares midnights rather than using Truncate, which rounds against the
// epoch in UTC and so puts the day boundary at the zone's offset instead of at
// local midnight - on a +08:00 machine everything recorded before eight in the
// morning would be dated to the day before. The half-day added before dividing
// absorbs the 23- and 25-hour days daylight saving produces, which would
// otherwise shift a label by one twice a year.
func calendarDaysBetween(t, now time.Time) int {
	midnight := func(v time.Time) time.Time {
		y, m, d := v.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, v.Location())
	}
	return int((midnight(now).Sub(midnight(t)) + 12*time.Hour) / (24 * time.Hour))
}

// pausedUntilLabel renders a pause deadline for the window, and is empty both
// when protection is on and when the pause has no deadline - the frontend tells
// those apart by the paused flag, and says "until you turn it back on" for the
// second.
func pausedUntilLabel(p scm.PauseState) string {
	if !p.Paused || p.Until.IsZero() {
		return ""
	}
	return p.Until.Local().Format("Mon 2 Jan, 15:04")
}
