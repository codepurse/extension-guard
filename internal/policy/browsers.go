package policy

import (
	"sort"
	"strings"
)

// This file answers the one question the rest of the guard never asks: what is
// on this machine that the guard cannot manage?
//
// Everything else in this package enforces something. A browser the guard has
// never heard of is the opposite - there is nothing to apply, and so nothing to
// notice. Chrome, Edge, Brave and Firefox read the enterprise policies the guard
// writes; Opera does not, Vivaldi does not, and a copy of Tor Browser unpacked
// into a user's own directory reads no policy the guard has written and carries
// no extension it has locked. Every site on the block list is one download away
// while the status window still reads "protection active" - which is the one
// failure this project refuses to ship.
//
// So the gap is reported, and deliberately not enforced from here. The reason is
// the one at the top of categories.go: what is blocked has to keep living in the
// config, where the person bound by it can read it. A guard that closed a browser
// because a list inside the binary named it would be enforcing a rule nobody
// agreed to, and that list would widen on every update. What this file does is
// find the hole and name it; blocking it is `guard block-category browsers`, an
// ordinary category expanding into ordinary rules.
//
// It is also deliberately not an enforce.Status row, which is where a reader
// would look for it first. Those are enforcement facts, and the service counts
// the enforced ones to decide whether a re-apply actually corrected anything
// (see enforce.EnforcedCount). A row that is present and can never be enforced
// would read as permanent tamper and have the service log a correction every
// thirty seconds for as long as Opera stayed installed.

// managedImages maps the executable of every browser the guard writes policy for
// to its Kind. Classification is by image name because that is what a browser
// registration reliably gives us, and because it is the same handle an exe rule
// blocks by - so a browser this calls unmanaged is one the browsers category can
// actually name.
//
// The caveat is Firefox forks. Tor Browser, LibreWolf and Waterfox are Firefox
// underneath, and Tor Browser ships its executable under Firefox's own name - so
// a Tor Browser registration is indistinguishable here from Firefox itself and
// reads as managed. That is why the browsers category blocks Tor by tor.exe, the
// daemon it cannot reach the network without, rather than trusting either the
// name or the policy: whether a hardened fork honours the Firefox policy key the
// guard writes is not something this code can know, and guessing towards
// "managed" is guessing towards a hole.
var managedImages = map[string]Kind{
	"chrome.exe":  Chrome,
	"msedge.exe":  Edge,
	"brave.exe":   Brave,
	"firefox.exe": Firefox,
}

// InstalledBrowser is one browser this machine has registered as a browser.
type InstalledBrowser struct {
	// Name is the display name from the registration ("Opera Stable",
	// "Vivaldi"), which is what a person recognizes. It can be empty when the
	// registration carries no readable name - see Label.
	Name string
	// Exe is the full path to the executable, when the registration gave one.
	// Empty is possible, for a half-removed or malformed registration, and is
	// reported rather than dropped: a browser the guard cannot locate is still a
	// browser it cannot manage.
	Exe string
	// Kind is the supported browser this is, or empty when the guard writes no
	// policy it reads. See Managed.
	Kind Kind
	// Missing is set when the registration names an executable that is not there.
	//
	// It is the fingerprint of a rename. Renaming opera.exe walks out of every
	// name-keyed rule, but it does not touch the registration that pointed at
	// opera.exe - so the machine is left claiming to have a browser installed at a
	// path with no file at it. That is worth surfacing precisely because the guard
	// cannot tell which of two things happened: the browser was uninstalled and
	// left a stale entry behind, or it was renamed to get out from under a block.
	// Both are shown as what they are and neither is called the other.
	Missing bool
}

// Managed reports whether the guard writes policy this browser reads - which is
// to say whether the locked extensions and the blocked sites apply inside it at
// all.
func (b InstalledBrowser) Managed() bool { return b.Kind != "" }

// Image is the executable's file name, which is what an exe rule blocks by.
func (b InstalledBrowser) Image() string { return baseName(normalizeWinPath(b.Exe)) }

// Label is what to show for this browser: its registered name, failing that the
// executable's name, and failing both something honest rather than a blank.
func (b InstalledBrowser) Label() string {
	if n := strings.TrimSpace(b.Name); n != "" {
		return n
	}
	if img := b.Image(); img != "" {
		return img
	}
	return "unnamed browser"
}

// ClassifyBrowser reports which supported browser an executable belongs to, or
// an empty Kind for one the guard cannot manage.
func ClassifyBrowser(exe string) Kind {
	return managedImages[strings.ToLower(baseName(normalizeWinPath(exe)))]
}

// browserScan is the machine scan, indirected so a test can supply a machine
// rather than depending on which browsers happen to be installed on the one
// running the tests. Same reason systemRootDir is a var. Production code always
// leaves it as the platform's scanBrowsers.
var browserScan = scanBrowsers

// RegisteredBrowsers lists every browser registered on this machine, classified
// into the ones the guard writes policy for and the ones it cannot manage.
//
// This is the only way in: the platform implementation is unexported so nothing
// can read the machine directly and quietly sidestep the seam above. A caller
// that bypassed it would be untestable, and would be the one place a test could
// not describe the machine it wanted.
func RegisteredBrowsers() []InstalledBrowser { return browserScan() }

// UnmanagedBrowsers is every registered browser the guard cannot manage. It is
// the raw finding, before asking whether anything is blocking them.
func UnmanagedBrowsers() []InstalledBrowser {
	var out []InstalledBrowser
	for _, b := range browserScan() {
		if !b.Managed() {
			out = append(out, b)
		}
	}
	return out
}

// BlocksBrowser reports whether any enabled app rule already covers this
// browser's executable.
//
// It asks by building the process the browser would be if it were running and
// handing that to the same matcher the sweep uses, rather than comparing strings
// itself. A rule naming Opera by image name, by full path, or by the folder it
// sits in then all answer yes here for exactly the reason each would close it a
// second after it started, and the two cannot drift apart.
//
// One kind cannot answer: a window-title rule matches titles, and a browser that
// is not running has none. So a browser blocked only by its window title reads as
// unblocked here. That errs towards warning about a gap which is in fact covered,
// and that is the direction to err in - the opposite is a silent hole, which is
// the thing this file exists to stop.
func (c Config) BlocksBrowser(b InstalledBrowser) bool {
	p := Process{Name: b.Image(), Path: normalizeWinPath(b.Exe)}
	if p.Name == "" && p.Path == "" {
		return false
	}
	for _, a := range c.BlockedApps() {
		if a.Matches(p) {
			return true
		}
	}
	return false
}

// VanishedBrowsers is every browser whose registration points at a file that is
// not there, and which the config is blocking.
//
// The "and which the config is blocking" half is what makes this worth warning
// about rather than noise. A browser nobody blocked whose executable is gone was
// almost certainly uninstalled, and warning about that would fire forever on any
// machine that ever removed a browser - which teaches the reader to ignore every
// warning this app prints, including the one that matters. A browser somebody
// went to the trouble of blocking, whose file has since disappeared, is the one
// case where the innocent explanation and the evasion are equally likely, and
// that is the one worth saying out loud.
func (c Config) VanishedBrowsers() []InstalledBrowser {
	var out []InstalledBrowser
	for _, b := range UnmanagedBrowsers() {
		if b.Missing && c.BlocksBrowser(b) {
			out = append(out, b)
		}
	}
	return out
}

// UnblockedBrowsers is the finding worth acting on: every browser on this machine
// that the guard can neither manage nor is blocking. Each one is a way around
// every site on the block list and every extension locked in place.
//
// Give it the whole config, not the schedule-resolved one. The question worth
// warning about is whether anything on the block list covers the browser at all: a
// browser blocked only on weekday afternoons is handled, and a warning that fired
// every evening would be complaining about a schedule the user chose. That such a
// block is idle right now is shown as "Waiting" wherever the state is listed,
// exactly as it is for a scheduled site - and, as there, it is not a fault.
//
// A registration whose executable is gone is left out too, for a different reason:
// there is no file there to run, so calling it reachable would be a warning that
// can never be cleared and that is wrong every time a browser is uninstalled.
// Those are VanishedBrowsers' business, and only when something was blocking them.
func (c Config) UnblockedBrowsers() []InstalledBrowser {
	var out []InstalledBrowser
	for _, b := range UnmanagedBrowsers() {
		if b.Missing {
			continue
		}
		if !c.BlocksBrowser(b) {
			out = append(out, b)
		}
	}
	return out
}

// exeFromCommand pulls the executable out of a registered open command, which is
// a command line rather than a path: "C:\...\opera.exe" -- "%1".
//
// Two shapes, because both occur. A quoted path is taken as it stands, which is
// what a correct registration writes. An unquoted one is taken up to and
// including the first ".exe", because an unquoted path containing spaces turns up
// often enough in real registrations that splitting on the first space would hand
// back "C:\Program" and quietly lose the browser.
func exeFromCommand(cmd string) string {
	s := strings.TrimSpace(cmd)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			return strings.TrimSpace(s[1 : 1+end])
		}
		return strings.TrimSpace(strings.Trim(s, `"`))
	}
	const ext = ".exe"
	if i := strings.Index(strings.ToLower(s), ext); i >= 0 {
		return strings.TrimSpace(s[:i+len(ext)])
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// sortBrowsers puts the list in a stable, readable order: the unmanaged first,
// because they are the reason anybody is reading it, then by label.
func sortBrowsers(list []InstalledBrowser) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Managed() != list[j].Managed() {
			return !list[i].Managed()
		}
		return strings.ToLower(list[i].Label()) < strings.ToLower(list[j].Label())
	})
}
