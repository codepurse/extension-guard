package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// This file adds the other way round: instead of naming what is blocked, name what
// is allowed and block everything else.
//
// It is the same mechanism as domains.go pointed the opposite direction. Chromium's
// URLBlocklist takes "*", which blocks every URL, and URLAllowlist overrides it
// entry by entry; Firefox's WebsiteFilter takes "<all_urls>" in Block and the same
// exceptions in Exceptions. So a study mode that leaves three reference sites
// reachable and nothing else costs no new enforcement surface at all - it is two
// more values in the hive the tamper watcher already watches.
//
// Why it is a mode rather than an entry on the block list. NormalizeDomain refuses
// a bare "*" on purpose, because reaching "block every URL" through the box you
// type reddit.com into would take the whole web out by typo. That refusal is right
// and it stays; this is the deliberate door, and it is deliberately somewhere else.
//
// The gate inverts twice, which is worth reading slowly because it is the opposite
// of the block list in both halves:
//
//   - Turning the mode *on* blocks the entire web, so it only strengthens: admin,
//     no password. Turning it *off* unblocks the entire web: password.
//   - Adding a site to the allowlist *opens* something that was blocked, so it
//     weakens: password. Removing one closes it again: free.
//
// So on the block list "add" is free and "remove" costs the password, and here it
// is the other way round. AllowNarrows is the one place that decides, for the same
// reason Block.Narrows is.

// Allowlist is the "only these sites" mode.
//
// On is the mode itself. Sites survives it being switched off, exactly as a
// disabled Domain stays on the block list: the list is what you built, and having
// to build it again to turn the mode back on would make the mode unusable.
//
// Windows, when present, are when the mode applies - the study-mode shape, where
// the web closes at nine and opens again at five. Empty means around the clock. A
// window here means exactly what it means on a Block, and is resolved by the same
// code.
type Allowlist struct {
	On      bool     `json:"on,omitempty"`
	Sites   []string `json:"sites,omitempty"`
	Windows []Window `json:"windows,omitempty"`
}

// maxAllowEntries is Chromium's ceiling on URLAllowlist, the same one URLBlocklist
// has and for the same reason: going over it does not error, the browser silently
// ignores the excess, and an allowlist whose tail is ignored is a page the user
// believes is reachable and is not.
const maxAllowEntries = maxDomainEntries

// ChromiumBlockAll is the URLBlocklist entry that blocks every URL. It is the one
// place this string is written, so nothing else in the package has to know that a
// bare asterisk is what Chromium means by "everything".
const ChromiumBlockAll = "*"

// FirefoxBlockAll is Firefox's equivalent in WebsiteFilter/Block.
const FirefoxBlockAll = "<all_urls>"

// ChromiumAllowPattern is the URLAllowlist entry for a normalized host. Same shape
// as the blocklist's: Chromium reads a bare hostname as host-and-subdomains across
// every scheme and path, so one entry covers en.wikipedia.org too.
func ChromiumAllowPattern(host string) string { return host }

// FirefoxAllowPattern is the WebsiteFilter/Exceptions match pattern for a host.
func FirefoxAllowPattern(host string) string { return "*://*." + host + "/*" }

// Allowing returns the allowlist the config carries, with a nil pointer reading as
// "no such mode". Every caller wants a value it can ask questions of.
func (c Config) Allowing() Allowlist {
	if c.Allowlist == nil {
		return Allowlist{}
	}
	return *c.Allowlist
}

// AllowlistOn reports whether the mode is enforcing at this moment: switched on,
// and inside one of its windows if it has any.
//
// The two halves are separate questions and the window is the one that moves, so
// this is what enforcement asks and Allowing().On is what the config says. A window
// that has closed is not the mode being off - the status surfaces say "waiting"
// rather than "off" for exactly that reason.
func (c Config) AllowlistOn(at time.Time) bool {
	a := c.Allowing()
	if !a.On {
		return false
	}
	return a.InWindow(at)
}

// InWindow reports whether the moment falls inside one of the allowlist's windows.
// No windows means always, which is what an unqualified "only these sites" means.
func (a Allowlist) InWindow(at time.Time) bool {
	if len(a.Windows) == 0 {
		return true
	}
	for _, w := range a.Windows {
		if w.Active(at) {
			return true
		}
	}
	return false
}

// AllowedSites returns the normalized hosts to allow, deduplicated and sorted, with
// anything unparseable left out - Validate is what reports those, exactly as it does
// for the block list.
func (a Allowlist) AllowedSites() []string {
	seen := make(map[string]bool, len(a.Sites))
	out := make([]string, 0, len(a.Sites))
	for _, s := range a.Sites {
		host, err := NormalizeDomain(s)
		if err != nil || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

// HasAllowed reports whether a host is already on the allowlist.
func (a Allowlist) HasAllowed(host string) bool {
	for _, s := range a.AllowedSites() {
		if s == host {
			return true
		}
	}
	return false
}

// ScheduleSummary renders the allowlist's timetable the way a Block's does, so the
// two read identically wherever they are listed side by side.
func (a Allowlist) ScheduleSummary() string {
	if len(a.Windows) == 0 {
		return "always"
	}
	parts := make([]string, 0, len(a.Windows))
	for _, w := range a.Windows {
		parts = append(parts, w.Summary())
	}
	return strings.Join(parts, ", ")
}

// AllowNarrows reports whether a change to the allowlist would weaken protection
// rather than strengthen it, which is what decides the gate. It is the analogue of
// Block.Narrows and, like it, is the single place the question is answered - the
// CLI asks it and the elevated guard asks it again, so the status window cannot
// skip it.
//
// The four cases, and why each falls where it does:
//
//   - Turning the mode on blocks the entire web. Strengthening.
//   - Turning it off unblocks the entire web. Weakening, and the largest one in
//     this program.
//   - Allowing a site opens something that was blocked. Weakening.
//   - Un-allowing one closes it again. Strengthening.
//
// A window is the fifth case and is handled by AllowWindowNarrows, because setting
// one is not a change to the same shape.
func AllowNarrows(action string) bool {
	switch action {
	case AllowActionOff, AllowActionAllow:
		return true
	}
	return false
}

// The actions AllowNarrows judges.
const (
	AllowActionOn      = "on"
	AllowActionOff     = "off"
	AllowActionAllow   = "allow"
	AllowActionUnallow = "unallow"
)

// AllowWindowNarrows reports whether giving the mode this timetable weakens it.
// Going from "around the clock" to "only these hours" does, for the reason
// add-block with a window does: it takes something enforced all day and enforces it
// only sometimes. Setting a window on a mode that is off changes nothing that is
// being enforced, so it does not.
func (c Config) AllowWindowNarrows(windows []Window) bool {
	a := c.Allowing()
	if !a.On {
		return false
	}
	if len(windows) == 0 {
		return false // going back to around the clock only ever widens enforcement
	}
	return len(a.Windows) == 0
}

// SetAllowlistOn turns the mode on or off, reporting whether anything changed.
//
// The pointer is allocated on first use and dropped when the mode is off with no
// sites left, so a config that never used the mode - or used it and stopped, having
// emptied the list - encodes byte-identically to one written before it existed. See
// Config.Canonical, which the trusted copy is compared on.
func (c *Config) SetAllowlistOn(on bool) bool {
	a := c.Allowing()
	if a.On == on {
		return false
	}
	a.On = on
	c.setAllowlist(a)
	return true
}

// SetAllowlistWindow replaces the mode's timetable. An empty slice means around the
// clock.
func (c *Config) SetAllowlistWindow(windows []Window) bool {
	a := c.Allowing()
	if sameWindows(a.Windows, windows) {
		return false
	}
	a.Windows = windows
	c.setAllowlist(a)
	return true
}

// AddAllowed puts a site on the allowlist, returning the normalized host.
//
// It refuses a host the block list already covers. Chromium gives an allowlist
// entry precedence over a blocklist entry of the same specificity, so accepting
// both would make `guard domains` report a site as blocked while the browser let it
// through - the one class of disagreement this project refuses to ship. Which way
// to resolve it is the user's call, and it is a decision with a password on it
// either way, so it is theirs to make explicitly rather than ours to guess.
func (c *Config) AddAllowed(name string) (string, bool, error) {
	host, err := NormalizeDomain(name)
	if err != nil {
		return "", false, err
	}
	if covered, ok := c.CoveredBy(host); ok {
		return host, false, fmt.Errorf("%s is on the block list (as %s), so allowing it would contradict it; "+
			"unblock it first with `guard unblock-domain %s`", host, covered, covered)
	}
	a := c.Allowing()
	if a.HasAllowed(host) {
		return host, false, nil
	}
	if len(a.AllowedSites()) >= maxAllowEntries {
		return host, false, fmt.Errorf("the allowlist already holds %d sites, which is as many as the browsers honour",
			maxAllowEntries)
	}
	a.Sites = append(a.Sites, host)
	c.setAllowlist(a)
	return host, true, nil
}

// RemoveAllowed takes a site off the allowlist, returning the normalized host.
func (c *Config) RemoveAllowed(name string) (string, bool) {
	host, err := NormalizeDomain(name)
	if err != nil {
		host = strings.ToLower(strings.TrimSpace(name))
	}
	a := c.Allowing()
	kept := make([]string, 0, len(a.Sites))
	removed := false
	for _, s := range a.Sites {
		if norm, err := NormalizeDomain(s); err == nil && norm == host {
			removed = true
			continue
		}
		kept = append(kept, s)
	}
	if !removed {
		return host, false
	}
	a.Sites = kept
	c.setAllowlist(a)
	return host, true
}

// setAllowlist stores the value, dropping the object entirely when it says nothing.
// See SetAllowlistOn for why that matters to the trusted copy.
func (c *Config) setAllowlist(a Allowlist) {
	if !a.On && len(a.Sites) == 0 && len(a.Windows) == 0 {
		c.Allowlist = nil
		return
	}
	copied := a
	copied.Sites = append([]string(nil), a.Sites...)
	copied.Windows = append([]Window(nil), a.Windows...)
	c.Allowlist = &copied
}

// validateAllowlist refuses a mode that would behave in a way its author did not
// intend, on the same principle as the rest of Validate.
func (c Config) validateAllowlist() error {
	if c.Allowlist == nil {
		return nil
	}
	a := *c.Allowlist
	for _, s := range a.Sites {
		host, err := NormalizeDomain(s)
		if err != nil {
			return fmt.Errorf("allowlist: %w", err)
		}
		// The same contradiction AddAllowed refuses, caught again here: a config that
		// reached this shape by hand must not enforce a blocklist entry the browser is
		// going to override.
		if covered, ok := c.CoveredBy(host); ok {
			return fmt.Errorf("allowlist: %s is also on the block list (as %s), and the browsers would let it through",
				host, covered)
		}
	}
	if len(a.AllowedSites()) > maxAllowEntries {
		return fmt.Errorf("allowlist: %d sites, but the browsers honour only %d", len(a.AllowedSites()), maxAllowEntries)
	}
	for i, w := range a.Windows {
		start, okStart := parseHM(w.Start)
		end, okEnd := parseHM(w.End)
		if !okStart {
			return fmt.Errorf("allowlist window %d: bad start time %q (want HH:MM)", i, w.Start)
		}
		if !okEnd {
			return fmt.Errorf("allowlist window %d: bad end time %q (want HH:MM)", i, w.End)
		}
		if start == end {
			return fmt.Errorf("allowlist window %d: start and end are both %q, so it never applies", i, w.Start)
		}
		for _, d := range w.Days {
			if _, ok := parseWeekday(d); !ok {
				return fmt.Errorf("allowlist window %d: unknown day %q", i, d)
			}
		}
	}
	return nil
}

// sameWindows reports whether two timetables say the same thing, so a no-op edit is
// not written to the config and does not spend a UAC prompt.
func sameWindows(a, b []Window) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Start != b[i].Start || a[i].End != b[i].End || len(a[i].Days) != len(b[i].Days) {
			return false
		}
		for j := range a[i].Days {
			if !strings.EqualFold(a[i].Days[j], b[i].Days[j]) {
				return false
			}
		}
	}
	return true
}
