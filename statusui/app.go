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
	// Categories are the built-in curated sets, with enough state on each row for
	// the window to say whether blocking it would do anything. They come down with
	// the rest of the status rather than through their own call, because every
	// other list here arrives in one round trip and a second one would let the
	// category cards disagree with the app rows they sit above.
	Categories []CategoryRow `json:"categories"`
	// Hardening is the pinned browser settings - the ones that decide whether
	// locking an extension means anything inside the browsers the guard *does*
	// manage.
	Hardening []HardeningRow `json:"hardening"`
	// Allowlist is the "only these sites" mode: the other way round from Domains,
	// and the one place in this window where adding to a list weakens protection
	// rather than strengthening it.
	Allowlist AllowlistPanel `json:"allowlist"`
	// Usage is how long each blocked application actually ran. It comes down with
	// the rest of the status for the reason the category rows do: everything here
	// arrives in one round trip, and a second call would let this disagree with the
	// app rows it sits beside.
	Usage UsagePanel `json:"usage"`
	// PrivateBrowsingOpen is the hole those settings close, reported whether or not
	// anything is hardened: an extension cannot be force-installed into a private
	// or guest window, so while this is true every filter the guard installs is one
	// keystroke from being off. It is the in-window twin of the Unmanaged list
	// below - a window reading "protection active" over an available Ctrl+Shift+N
	// is the same true statement doing the same false work.
	PrivateBrowsingOpen bool `json:"privateBrowsingOpen"`
	// Unmanaged are the browsers installed here that the guard writes no policy
	// for - the ones through which every blocked site is reachable and none of the
	// locked extensions are loaded. It is the one list in this struct that is not
	// about something the guard is doing; it is about what it cannot do, which is
	// why the window shows it whether or not anything else needs attention.
	Unmanaged []UnmanagedRow `json:"unmanaged"`
	// UnmanagedScanned reports whether the machine could be scanned at all. An
	// empty Unmanaged list means "nothing found" when this is true and nothing
	// whatsoever when it is false, and the window must not print a clean bill of
	// health for a scan that never ran. See policy.BrowserScanSupported.
	UnmanagedScanned bool `json:"unmanagedScanned"`

	// StaleGecko names the Firefox-family browsers that are still running the
	// instance that was open when the rules last changed. They show what they read
	// at startup and cannot be told to re-read, so the window carries a standing
	// notice for as long as this is non-empty - the one caveat that outlives the
	// message confirming the change.
	StaleGecko []string `json:"staleGecko"`
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

// AllowlistPanel is the allowed-sites-only mode as the window offers it.
//
// On is what the config says and Enforcing is whether it applies at this moment -
// the two differ while the mode has a timetable whose window is shut, and the window
// says "waiting" for that rather than "off", because "off" would read as somebody
// having turned it off.
type AllowlistPanel struct {
	On        bool     `json:"on"`
	Enforcing bool     `json:"enforcing"`
	Schedule  string   `json:"schedule"`
	Sites     []string `json:"sites"`
	// Shut is the state worth its own flag: the mode is on and the allowlist is
	// empty, so every page in every managed browser is refused. It is a legitimate
	// thing to want - it is what "block the entire internet" means - and it is also
	// the state somebody reaches by accident, so the window says which it is looking
	// at rather than showing an empty list.
	Shut bool `json:"shut"`
}

// UsagePanel is the record of how long each blocked application actually ran.
//
// Durations arrive pre-formatted rather than as numbers, for the reason the block
// rows do: policy.HumanDuration is what the CLI prints, and two renderers of the
// same duration eventually disagree about what "1h30m" looks like.
//
// Span and the sum of the rows are both reported because they answer different
// questions - an hour with two applications open is two hours of rules and one hour
// of the afternoon. See policy.UsageReport.
type UsagePanel struct {
	Rows  []UsageRow `json:"rows"`
	Days  []UsageDay `json:"days"`
	Today string     `json:"today"`
	Total string     `json:"total"`
	// Span is how many days Total covers, so the column can be labelled without the
	// frontend hard-coding a number the backend chose.
	Span int `json:"span"`
	// Measured is false when no application rule is configured, so the window says
	// there is nothing to measure rather than showing an empty list that reads as a
	// broken feature.
	Measured bool `json:"measured"`
	// Unreadable means the record could not be parsed. Unlike a limit it does not
	// fail closed - there is no budget here to protect - so the window says the
	// history is missing and shows nothing rather than showing zeroes as if they
	// were measurements.
	Unreadable bool `json:"unreadable"`
}

// UsageRow is one application's share of the record. Gone marks one the block list
// no longer holds; those rows stay, because time spent on something later unblocked
// is still time spent.
type UsageRow struct {
	Label  string `json:"label"`
	Detail string `json:"detail"`
	Today  string `json:"today"`
	Total  string `json:"total"`
	Gone   bool   `json:"gone"`
	// Percent is this row's share of the busiest row, for the bar width. Computed
	// here so the bar cannot disagree with the number printed next to it.
	Percent int `json:"percent"`
}

// UsageDay is one day of the span. Label is the weekday and date as a person reads
// it; Percent is scaled to the busiest day rather than to a fixed number of hours,
// because a fixed scale makes a quiet week look like a broken feature.
type UsageDay struct {
	Day     string `json:"day"`
	Label   string `json:"label"`
	Spent   string `json:"spent"`
	Percent int    `json:"percent"`
}

// HardeningRow is one pinned browser setting as the window offers it. State is
// the word the row reads ("blocked", "strict", "off") rather than a bool, because
// SafeSearch has two on-states and which one is in force is the part a reader
// cannot guess. Browsers names where the setting reaches, and Gap says where it
// does not - a setting shown as on while it is silently absent from Firefox is
// exactly the kind of half-truth this window exists to avoid.
type HardeningRow struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Note     string `json:"note"`
	State    string `json:"state"`
	On       bool   `json:"on"`
	Level    string `json:"level"`
	Browsers string `json:"browsers"`
	Gap      string `json:"gap"`
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
	// Category is the id of the built-in set that added this rule, empty for one
	// the user added themselves. It only groups the list; nothing about how the
	// rule is enforced depends on it. See policy.App.Source.
	Category string `json:"category"`
}

// CategoryRow is one built-in category as the window offers it. Apps, Domains and
// Settings are what the category covers in total; Missing is how much of that the
// config does not hold yet, which is the difference between a button that would
// block nineteen new sites and one that would do nothing at all.
//
// Blocked means the category is in force - its block exists, or, for a category
// that names no rules, every setting it asks for is on. The two are independent:
// a category can be in force and still have entries missing, which is exactly the
// state a user is in after the catalog gains an app in an update.
type CategoryRow struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Note     string `json:"note"`
	Apps     int    `json:"apps"`
	Domains  int    `json:"domains"`
	Settings int    `json:"settings"`
	// Blocks is false for a category that names no rules and only turns browser
	// settings on. The window says "On" rather than "Blocked" for one of those,
	// and offers neither a schedule nor a lock, because there is no block to put
	// on one - see policy.Category.BlocksAnything.
	Blocks  bool `json:"blocks"`
	Blocked bool `json:"blocked"`
	Missing int  `json:"missing"`
	// Items is everything the category covers, so the window can show the list
	// before the user agrees to it. A category is accepted all at once and comes
	// off again only with the password, so a count is not something a person can
	// meaningfully consent to - they have to be able to read what is in it.
	Items []CategoryItem `json:"items"`
}

// CategoryItem is one entry of a category as the window lists it. Present marks
// what the config already holds, which is what stops a top-up of three entries
// reading as twenty-eight new restrictions.
type CategoryItem struct {
	Kind  string `json:"kind"` // "app", "site" or "setting"
	Label string `json:"label"`
	// Detail is what the entry covers, in policy's own words. It carries the one
	// distinction a list of friendly names loses: "Google Play Games" blocks a
	// whole directory and "Steam" blocks one executable, and somebody deciding
	// whether to accept the category needs to see which is which.
	Detail  string `json:"detail"`
	Present bool   `json:"present"`
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
	// Restart names the browsers that will not see this change until they are
	// restarted, or "" when there are none. It is a field of its own rather than a
	// sentence glued onto Message because the two have different lifetimes: the
	// message is a confirmation and can fade, while this is an outstanding
	// instruction and has to stay on screen until it is dealt with. Gluing them
	// together is what made the caveat disappear seven seconds after a UAC prompt
	// the user was still looking at.
	Restart string `json:"restart,omitempty"`
}

// BrowserRow is one row in the status list.
type BrowserRow struct {
	Kind      string `json:"kind"`
	Installed bool   `json:"installed"`
	Locked    bool   `json:"locked"`
	Detail    string `json:"detail"`
}

// UnmanagedRow is one browser the guard cannot filter, and what is being done
// about it.
//
// Listed and Blocked are the same pair the domain and app rows carry, and for the
// same reason: a browser on the block list under a weekday-afternoon window is
// genuinely blocked and genuinely reachable at eight in the evening, and one badge
// cannot say both. Exe is shown because it is what the user needs in order to
// block a browser the built-in category does not name.
type UnmanagedRow struct {
	Label   string `json:"label"`
	Exe     string `json:"exe"`
	Listed  bool   `json:"listed"`
	Blocked bool   `json:"blocked"`
	// Missing means the executable this registration names is not there, which is
	// what a rename leaves behind: renaming a file walks out of every name-keyed
	// rule but does not touch the registration that pointed at it. It outranks the
	// other two in the window, because "blocked" and "reachable" are both claims
	// about a file, and this one says the file is absent.
	Missing bool `json:"missing"`
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
			Category:  categoryOf(raw),
		})
	}

	cats := make([]CategoryRow, 0, len(policy.CategoryIDs()))
	for _, id := range policy.CategoryIDs() {
		cat, ok := policy.LookupCategory(id)
		if !ok {
			continue
		}
		// CategoryApplied rather than Block: a settings-only category has no
		// block to find, and would otherwise read "available" forever.
		applied := a.cfg.CategoryApplied(cat)
		entries := a.cfg.CategoryEntries(cat)
		items := make([]CategoryItem, 0, len(entries))
		for _, e := range entries {
			items = append(items, CategoryItem{Kind: e.Kind, Label: e.Label, Detail: e.Detail, Present: e.Present})
		}
		cats = append(cats, CategoryRow{
			ID:       cat.ID,
			Label:    cat.Label,
			Note:     cat.Note,
			Apps:     len(cat.Apps),
			Domains:  len(cat.Domains),
			Settings: len(cat.Settings),
			Blocks:   cat.BlocksAnything(),
			Blocked:  applied,
			Missing:  a.cfg.CategoryMissing(cat),
			Items:    items,
		})
	}

	// Every browser the guard has no policy for, whether or not a rule covers it.
	// The blocked ones stay in the list on purpose: a section that emptied itself
	// once the category was applied would leave the user with no way to see that
	// Opera is still installed and still handled, and no place to notice the day a
	// new browser appears next to it.
	unmanaged := make([]UnmanagedRow, 0)
	for _, b := range policy.UnmanagedBrowsers() {
		unmanaged = append(unmanaged, UnmanagedRow{
			Label:   b.Label(),
			Exe:     b.Exe,
			Listed:  a.cfg.BlocksBrowser(b),
			Blocked: active.BlocksBrowser(b),
			Missing: b.Missing,
		})
	}

	// The pinned browser settings, read from the whole config rather than the
	// resolved one: these are not schedulable, so there is no window for them to be
	// outside of, and reading them from `active` would only invite a future reader
	// to assume there is.
	hardened := a.cfg.Hardened()
	hardening := make([]HardeningRow, 0, len(policy.Knobs))
	for _, knob := range policy.Knobs {
		row := HardeningRow{
			ID:       knob.ID,
			Label:    knob.Label,
			Note:     knob.Note,
			State:    hardened.Describe(knob.ID),
			On:       hardened.On(knob.ID),
			Browsers: hardeningBrowsers(knob.ID),
		}
		if knob.ID == policy.KnobSafeSearch {
			row.Level, _ = hardened.SafeSearchOn()
		}
		if missing := hardeningMissing(knob.ID); missing != "" {
			reason := knob.Gap
			if reason == "" {
				reason = "there is no policy for it"
			}
			row.Gap = "Not enforced in " + missing + " - " + reason + "."
		}
		hardening = append(hardening, row)
	}

	allow := a.cfg.Allowing()
	allowPanel := AllowlistPanel{
		On:        allow.On,
		Enforcing: a.cfg.AllowlistOn(now),
		Schedule:  allow.ScheduleSummary(),
		Sites:     allow.AllowedSites(),
	}
	allowPanel.Shut = allow.On && len(allowPanel.Sites) == 0

	usagePanel := buildUsagePanel(a.cfg.UsageStats(now, usageWindowDays))

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
		ServiceRunning:      scm.IsRunning(guardsvc.ServiceName),
		Disabled:            pause.Paused,
		PausedUntil:         pausedUntilLabel(pause),
		LockedCount:         locked,
		HasPassword:         hasPw,
		Browsers:            rows,
		Extensions:          exts,
		Blocks:              blocks,
		Domains:             domains,
		Apps:                apps,
		Categories:          cats,
		Hardening:           hardening,
		Usage:               usagePanel,
		Allowlist:           allowPanel,
		PrivateBrowsingOpen: a.cfg.PrivateBrowsingOpen(),
		Unmanaged:           unmanaged,
		UnmanagedScanned:    policy.BrowserScanSupported(),
		StaleGecko:          policy.BrowserNameList(policy.StaleGecko()),
		UsageError:          usageErr,
		ScheduleError:       scheduleErr,
	}
}

// categoryOf reads the category a rule came from off its source stamp. A source
// naming a category this build no longer ships is still returned, so the rule
// stays grouped where the config says it belongs rather than appearing to have
// been added by hand.
func categoryOf(a policy.App) string {
	src := strings.TrimSpace(a.Source)
	if !strings.HasPrefix(src, policy.SourcePrefix) {
		return ""
	}
	return strings.TrimPrefix(src, policy.SourcePrefix)
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
	return withRestartNote(a.execGuard(
		[]string{"-config", a.cfgPath, "block-domain", name},
		"Blocked, including every subdomain."))
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
	return withRestartNote(a.execGuard(args, name+" is no longer filtered."))
}

// withRestartNote records the one caveat a site block still has. Chrome, Edge and
// Brave are made to re-read their policy as part of applying the change, so they
// honour it within a second or two - but Firefox and Zen read their policies only
// when they start and offer no way to reload them, so a change made while one of
// them is open does not reach it until it is restarted. Naming only the ones
// actually running keeps the note off the machines it does not apply to.
//
// It is applied to the finished result rather than to the message beforehand, so
// the browsers it names are the ones still running when the change landed.
func withRestartNote(res ActionResult) ActionResult {
	if !res.OK {
		return res // nothing was applied, so there is nothing to restart for
	}
	running := policy.GeckoRunning()
	if len(running) == 0 {
		return res
	}
	verb, subject := "reads", "it starts"
	if len(running) > 1 {
		verb, subject = "read", "they start"
	}
	res.Restart = fmt.Sprintf("%s %s these rules only when %s, so this change is not active there yet. Restart %s to apply it.",
		policy.BrowserNames(running), verb, subject,
		map[bool]string{true: "them", false: "it"}[len(running) > 1])
	return res
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

// BlockCategory expands a built-in category into the block list: every
// application and site it names, governed by one always-on block under the
// category's id. Free of the password for the same reason BlockApp is - it only
// adds protection - but elevated, because it writes browser policy and the
// launch blocks.
//
// Running it on a category that is already blocked tops it up rather than
// failing, so the same button carries a user through a catalog that gained
// entries in an update. The frontend labels it from CategoryRow.Missing.
//
// Lifting one is deliberately not here. A category expands into ordinary rules
// and an ordinary block, so it comes off through RemoveBlock and UnblockApp -
// which take the password, because those are the steps that weaken.
func (a *App) BlockCategory(id string) ActionResult {
	cat, ok := policy.LookupCategory(id)
	if !ok {
		return ActionResult{Message: "No such category."}
	}
	// Answered here rather than by spending a UAC prompt to be told nothing
	// changed. This is the state a user lands in by pressing the button twice.
	if a.cfg.CategoryMissing(cat) == 0 && a.cfg.CategoryApplied(cat) {
		if cat.BlocksAnything() {
			return ActionResult{OK: true, Message: cat.Label + " is already blocked in full."}
		}
		return ActionResult{OK: true, Message: "Every setting " + cat.Label + " asks for is already on."}
	}
	args := []string{"-config", a.cfgPath, "block-category", cat.ID}
	// A category that blocks nothing is turned on, not blocked. The message is
	// what the user reads back when something still opens, so it has to say which
	// of the two actually happened.
	done := cat.Label + " is blocked, around the clock."
	if !cat.BlocksAnything() {
		done = cat.Label + " is on."
	}
	return a.execGuard(args, done)
}

// usageWindowDays is the span the window shows. A week is the unit people think
// in, and seven bars fit a narrow panel; `guard usage <days>` reaches further back
// into the same record.
const usageWindowDays = 7

// usageTopRows caps how many applications the window lists. The point of the panel
// is "what is taking the time", which the top few answer; a machine with a blocked
// category has forty rules and a list of forty rows nobody reads is not a better
// answer. The CLI prints them all.
const usageTopRows = 8

// buildUsagePanel turns the report into rows the window can render, scaling each
// bar to the busiest entry in its own list.
func buildUsagePanel(rep policy.UsageReport) UsagePanel {
	panel := UsagePanel{
		Span:       len(rep.Days),
		Measured:   rep.Measured,
		Unreadable: rep.Unreadable,
		Today:      policy.HumanDuration(rep.TodaySpan),
		Total:      policy.HumanDuration(rep.TotalSpan),
	}
	if rep.Unreadable {
		return panel
	}

	rows := rep.Rows
	if len(rows) > usageTopRows {
		rows = rows[:usageTopRows]
	}
	var peakRow time.Duration
	for _, r := range rows {
		if r.Total > peakRow {
			peakRow = r.Total
		}
	}
	for _, r := range rows {
		panel.Rows = append(panel.Rows, UsageRow{
			Label:   r.Label,
			Detail:  r.Detail,
			Today:   policy.HumanDuration(r.Today),
			Total:   policy.HumanDuration(r.Total),
			Gone:    r.Gone,
			Percent: sharePercent(r.Total, peakRow),
		})
	}

	var peakDay time.Duration
	for _, d := range rep.ByDay {
		if d > peakDay {
			peakDay = d
		}
	}
	for i, day := range rep.Days {
		spent := rep.ByDay[i]
		panel.Days = append(panel.Days, UsageDay{
			Day:     day,
			Label:   dayLabel(day),
			Spent:   policy.HumanDuration(spent),
			Percent: sharePercent(spent, peakDay),
		})
	}
	return panel
}

// sharePercent is one value's share of the largest, floored at 1% for anything
// non-zero: a day with four minutes on it must not draw as an empty one, because an
// empty bar reads as "nothing happened" rather than "a little happened".
func sharePercent(v, peak time.Duration) int {
	if peak <= 0 || v <= 0 {
		return 0
	}
	pct := int(int64(v) * 100 / int64(peak))
	if pct == 0 {
		pct = 1
	}
	return pct
}

// dayLabel renders a ledger day key as a person reads it. An unparseable key is
// returned as it stands rather than replaced with a guess - it came from a file, and
// showing what is actually in there is more use than hiding it.
func dayLabel(day string) string {
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		return day
	}
	return t.Format("Mon 2 Jan")
}

// hardeningBrowsers names the browsers a setting can be enforced in, and
// hardeningMissing the ones it cannot. Both read policy.KnobSupported rather than
// a list of their own, so the window cannot claim coverage the writers do not
// have.
func hardeningBrowsers(knobID string) string {
	return strings.Join(hardeningKinds(knobID, true), ", ")
}

func hardeningMissing(knobID string) string {
	return strings.Join(hardeningKinds(knobID, false), ", ")
}

func hardeningKinds(knobID string, supported bool) []string {
	var out []string
	for _, k := range policy.AllKinds() {
		if policy.KnobSupported(knobID, k) == supported {
			out = append(out, string(k))
		}
	}
	return out
}

// Harden pins a browser setting. Free of the password - it only adds protection,
// the same gate as blocking a site - but elevated (UAC), because it writes browser
// policy and the trusted config.
//
// level is used only by safe-search, where it selects moderate or strict; the
// guard treats an empty level as strict, and the decision lives there rather than
// here so the window and the CLI agree.
//
// password is needed for the one change here that weakens protection: lowering a
// SafeSearch level that is already stricter. policy.Config.HardenWeakens decides,
// and the elevated guard re-checks it, so this cannot be skipped from the
// renderer - the same arrangement the New block form uses for a window.
func (a *App) Harden(id, level, password string) ActionResult {
	knob, ok := policy.LookupKnob(id)
	if !ok {
		return ActionResult{Message: "No such setting."}
	}
	// Answered here rather than by spending a UAC prompt to be told nothing
	// changed. Turning it on twice is the state a user lands in by double-clicking.
	if a.cfg.Hardened().On(knob.ID) && (level == "" || level == a.cfg.Hardened().Describe(knob.ID)) {
		return ActionResult{OK: true, Message: knob.Label + " is already pinned."}
	}
	args := []string{"-config", a.cfgPath}
	if a.cfg.HardenWeakens(knob.ID, level) && !scm.IsPaused() {
		pw, bad := passwordArgs(password, "filtering less than "+knob.ID+" currently does")
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
	}
	if strings.TrimSpace(level) != "" {
		args = append(args, "-level", level)
	}
	args = append(args, "harden", knob.ID)
	return withRestartNote(a.execGuard(args, knob.Label+" is pinned."))
}

// HardenNeedsPassword lets the window ask for the password only when the change
// actually calls for one, instead of prompting on every level change or - worse -
// discovering the requirement after the UAC prompt has already been spent. The
// answer is not trusted: Harden and the elevated guard both re-check it.
func (a *App) HardenNeedsPassword(id, level string) bool {
	return a.cfg.HardenWeakens(id, level) && !scm.IsPaused()
}

// Unharden hands a setting back. That weakens protection, so it requires the
// password - except while protection is in the authorized paused state, exactly as
// for a site or an extension.
func (a *App) Unharden(id, password string) ActionResult {
	knob, ok := policy.LookupKnob(id)
	if !ok {
		return ActionResult{Message: "No such setting."}
	}
	if !a.cfg.Hardened().On(knob.ID) {
		return ActionResult{OK: true, Message: knob.Label + " is already off."}
	}
	args := []string{"-config", a.cfgPath}
	if !scm.IsPaused() {
		pw, bad := passwordArgs(password, "turning off "+knob.ID)
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
	}
	args = append(args, "unharden", knob.ID)
	msg := knob.Label + " is no longer pinned."
	if knob.ID == policy.KnobPrivateBrowsing {
		msg += " Private windows work again, and in Chrome, Edge and Brave a locked extension" +
			" does not run in one."
	}
	return withRestartNote(a.execGuard(args, msg))
}

// AllowOnly turns the allowed-sites-only mode on or off.
//
// On only strengthens - it blocks the entire web - so it costs the Windows prompt
// alone. Off unblocks the entire web, which is the largest single weakening in this
// program, so it takes the password. policy.AllowNarrows decides and the elevated
// guard re-checks it.
func (a *App) AllowOnly(on bool, password string) ActionResult {
	if a.cfg.Allowing().On == on {
		state := "off"
		if on {
			state = "on"
		}
		return ActionResult{OK: true, Message: "Allowed sites only is already " + state + "."}
	}
	action := policy.AllowActionOn
	arg := "on"
	if !on {
		action, arg = policy.AllowActionOff, "off"
	}
	args := []string{"-config", a.cfgPath}
	if policy.AllowNarrows(action) && !scm.IsPaused() {
		pw, bad := passwordArgs(password, "turning off allowed-sites-only")
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
	}
	args = append(args, "allow-only", arg)

	msg := "Every site is blocked now except the allowlist."
	if !on {
		msg = "The web is reachable again, except what is on the block list."
	} else if len(a.cfg.Allowing().AllowedSites()) == 0 {
		msg = "Every site is blocked now - the allowlist is empty. Add the ones you need below."
	}
	return withRestartNote(a.execGuard(args, msg))
}

// Allow lets a site through the mode. This is the one "add" in the window that
// weakens protection, so while the mode is on it takes the password - the mirror of
// UnblockDomain, and the opposite of BlockDomain.
func (a *App) Allow(name, password string) ActionResult {
	if strings.TrimSpace(name) == "" {
		return ActionResult{Message: "Type a site to allow."}
	}
	if _, err := policy.NormalizeDomain(name); err != nil {
		// Answer an obviously bad entry immediately rather than spending a UAC prompt
		// to be told the same thing.
		return ActionResult{Message: capitalize(err.Error())}
	}
	// The contradiction guardrail, answered here as well as in the guard: a site the
	// block list covers would be let through by the browser anyway, and finding that
	// out after the prompt would be worse.
	if covered, ok := a.cfg.CoveredBy(name); ok {
		return ActionResult{Message: "That site is on the block list (as " + covered +
			"), so allowing it would contradict it. Stop blocking " + covered + " first."}
	}
	args := []string{"-config", a.cfgPath}
	if a.cfg.Allowing().On && !scm.IsPaused() {
		pw, bad := passwordArgs(password, "allowing a site through")
		if bad != nil {
			return *bad
		}
		args = append(args, pw...)
	}
	args = append(args, "allow", name)
	return withRestartNote(a.execGuard(args, "Allowed, including every subdomain."))
}

// Unallow closes a site again. Free of the password - it only strengthens, the
// mirror of BlockDomain.
func (a *App) Unallow(name string) ActionResult {
	if strings.TrimSpace(name) == "" {
		return ActionResult{Message: "No site selected."}
	}
	return withRestartNote(a.execGuard(
		[]string{"-config", a.cfgPath, "unallow", name},
		name+" is no longer allowed through."))
}

// AllowNeedsPassword lets the window prompt only when the change actually calls for
// one, instead of asking on every click or discovering the requirement after the UAC
// prompt has been spent. The answer is not trusted: the guard re-checks it.
func (a *App) AllowNeedsPassword(action string) bool {
	if scm.IsPaused() {
		return false
	}
	if action == policy.AllowActionAllow && !a.cfg.Allowing().On {
		// Nothing is being enforced, so adding to the list opens nothing.
		return false
	}
	return policy.AllowNarrows(action)
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
	// A console, but only when there is a typing challenge to answer in it.
	//
	// Everything the window does goes through an elevated guard launched with no
	// window at all, which is right until the guard needs to ask something. The
	// challenge cannot be answered down a hidden pipe, so with one configured the
	// guard gets a real console and asks there. -hold-console is what stops that
	// console closing on a failure before anybody has read why.
	//
	// The test is whether a challenge exists, not whether this particular action
	// would hit it: a strengthening action opens a console that closes again at
	// once, which is a flicker, and the alternative is every call site here having
	// to know whether it weakens - a fact that already lives in policy and would
	// then be duplicated by hand in a second place.
	_, challenge := scm.GetFrictionChars()
	if challenge {
		args = append([]string{"-hold-console"}, args...)
	}
	code, err := runElevatedAndWait(guardExe, args, challenge)
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
	// An update only strengthens, so it never meets the challenge and needs no
	// console of its own.
	code, err := runElevatedAndWait(guardExe, []string{"-config", a.cfgPath, "update"}, false)
	if err != nil {
		if errors.Is(err, errElevationCancelled) {
			return ActionResult{Message: "Cancelled at the Windows permission prompt."}
		}
		return ActionResult{Message: "Could not run the updater: " + err.Error()}
	}
	if code != 0 {
		return ActionResult{Message: fmt.Sprintf("The updater reported an error (exit code %d).", code)}
	}
	return ActionResult{OK: true, Message: "Update installed. Close and reopen Ward to use the new version."}
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
