package policy

import (
	"fmt"
	"sort"
	"strings"
)

// This file closes the hole that made every locked extension optional inside the
// browsers the guard already manages.
//
// A force-installed extension is installed in every profile, and its Remove
// button is greyed out - which is the whole promise of this app. What that
// promise does not cover is a window the extension does not run in. Chrome's own
// documentation is explicit: extensions cannot be force-installed into Incognito,
// and the remedy is to turn Incognito off. A guest profile is worse still, since
// it carries no extensions at all. So Ctrl+Shift+N is a bypass of every locked
// filter that needs no download, no administrator and no rename - while the
// status window reads "protection active". That is the one failure this project
// refuses to ship, and it is the same failure browsers.go exists to report for a
// browser the guard cannot filter at all.
//
// The second knob here is different in kind. SafeSearch is not a hole in
// anything - it is filtering the guard can perform with the mechanism it already
// owns, for free, because it is one more value in the same policy hive the tamper
// watcher already watches.
//
// Two decisions worth stating, because both had a tempting alternative:
//
//   - Nothing here is implicit. It would be defensible to argue that closing the
//     Incognito hole is part of what "lock this extension" already promised, and
//     to turn it on for everybody on upgrade. That is refused for the reason at
//     the top of categories.go: what is enforced has to keep living in the
//     config, where the person bound by it can read it, and an update that
//     silently widened enforcement would be this app's own premise pointed the
//     wrong way. The hole is *reported* whether or not it is closed - see
//     Config.PrivateBrowsingOpen - and closing it is an ordinary opt-in.
//   - Hardening is not schedulable. A block narrows what is enforced during
//     declared windows; there is no reading of "Incognito is disabled on
//     Tuesdays" worth the complexity, and a knob that is off half the time is a
//     knob that does nothing - the same reason limits.go refuses a limit it
//     cannot measure.

// Hardening is the set of browser settings the guard pins. A nil *Hardening on
// the config means none of it, which is what every config written before this
// existed says.
type Hardening struct {
	// PrivateBrowsing pins private/incognito browsing and guest profiles off.
	// Named for what it governs rather than for the switch's direction: true means
	// the guard is managing it, which everywhere else in this config means more
	// protection rather than less.
	PrivateBrowsing bool `json:"privateBrowsing,omitempty"`
	// SafeSearch is "", "off", "moderate" or "strict". Empty and "off" both mean
	// the guard does not manage it.
	SafeSearch string `json:"safeSearch,omitempty"`
}

// SafeSearch levels.
const (
	SafeSearchOff      = "off"
	SafeSearchModerate = "moderate"
	SafeSearchStrict   = "strict"
)

// Hardening knob ids, as the CLI and the status window name them.
const (
	KnobPrivateBrowsing = "private-browsing"
	KnobSafeSearch      = "safe-search"
)

// Knob is one hardening switch: what it is called, and what it does and does not
// cover. The note is printed when it is turned on, for the reason Category.Note
// exists - a switch that promises more than it delivers is worse than one that
// says where it stops.
type Knob struct {
	ID    string
	Label string
	Note  string
}

// Knobs is every hardening switch, in the order they are listed.
var Knobs = []Knob{
	{
		ID:    KnobPrivateBrowsing,
		Label: "Private browsing and guest profiles",
		Note: "This is the bypass that makes a locked extension optional: an extension cannot be " +
			"force-installed into an Incognito or private window, and a guest profile carries no " +
			"extensions at all, so every filter the guard installs is one keystroke from being off. " +
			"Turning this on disables private windows and guest profiles in Chrome, Edge, Brave, " +
			"Firefox and Zen. It does not cover a browser the guard writes no policy for - run " +
			"`guard browsers` for those - and it leaves ordinary named profiles alone, which need no " +
			"blocking because a machine-wide force-install reaches all of them.",
	},
	{
		ID:    KnobSafeSearch,
		Label: "SafeSearch and restricted mode",
		Note: "Forces Google and Bing SafeSearch and YouTube's restricted mode in Chrome, Edge and " +
			"Brave. The Firefox family has no policy for any of it, so this is not enforced in " +
			"Firefox or Zen and " +
			"`guard hardening` says so rather than reporting a setting that is not applied. It " +
			"filters search results and YouTube; it is not a substitute for the block list, and a " +
			"site reached directly is unaffected.",
	},
}

// knobSupport records which browsers can be made to honour each knob. It is a
// fact about the browsers rather than about the operating system, so it lives
// here and both the Windows registry writer and the Linux policy-file writer read
// it - a knob a browser has no setting for must not be reported as enforced on
// either platform.
//
// The Firefox family is absent from safe-search because Mozilla ships no policy
// for it, and a fork inherits the gap. There is no Preferences entry to lock
// either: SafeSearch is not a Firefox preference, it is something Google and Bing
// decide from the request. Naming the gap here is what lets `guard hardening` say
// "not available" instead of showing a row that looks enforced.
var knobSupport = map[string][]Kind{
	KnobPrivateBrowsing: {Chrome, Edge, Brave, Firefox, Zen},
	KnobSafeSearch:      {Chrome, Edge, Brave},
}

// KnobSupported reports whether a knob can be enforced in a browser at all.
//
// A fork found on this machine is not in the table above and cannot be: nobody
// listed it. It is answered for as the Firefox it is a fork of - private
// browsing yes, SafeSearch no - because that is a fact about Mozilla's policy
// engine, which is the thing every fork inherits along with the gap.
func KnobSupported(id string, k Kind) bool {
	supported := knobSupport[id]
	for _, s := range supported {
		if s == k {
			return true
		}
	}
	if !k.Gecko() {
		return false
	}
	for _, s := range supported {
		if s == Firefox {
			return true
		}
	}
	return false
}

// Gaps lists, in words, every browser a knob that is currently on cannot be
// enforced in. It is printed by `guard hardening` next to the settings rather
// than left to the knob's note, because a gap that only appears in documentation
// is one nobody reads on the day it matters.
func (h Hardening) Gaps() []string {
	var out []string
	for _, knob := range Knobs {
		if !h.On(knob.ID) {
			continue
		}
		var missing []string
		for _, k := range AllKinds() {
			if !KnobSupported(knob.ID, k) {
				missing = append(missing, string(k))
			}
		}
		if len(missing) > 0 {
			out = append(out, fmt.Sprintf("%s is not enforced in %s - there is no policy for it",
				knob.ID, strings.Join(missing, ", ")))
		}
	}
	return out
}

// PrivateBrowsingOpen reports the hole this file exists for: the guard is locking
// at least one extension, and private browsing is still available, so every
// filter those extensions perform is one keystroke from being off.
//
// It is a question about the config rather than about the machine, and it is
// deliberately not an enforcement row - the reasoning is the one in browsers.go.
// A row that is present and can never be enforced would read as permanent tamper
// and have the service log a correction every thirty seconds.
//
// The condition is "some extension is actually being force-installed", not merely
// "some extension is enabled". An extension whose targets are still REPLACE_*
// placeholders locks nothing, so warning about it would put this warning on a
// machine with no lock to sidestep - and a warning that is always on teaches the
// reader to skip past it on the day it means something. That is the same
// gating decision VanishedBrowsers makes for a browser whose executable is gone.
func (c Config) PrivateBrowsingOpen() bool {
	return c.LockingAnything() && !c.Hardened().PrivateBrowsing
}

// LockingAnything reports whether any enabled extension has a usable target for
// any browser - that is, whether the force-install policy has anything at all to
// write. It reuses the same two "is this target applyable" checks the writers do,
// so it cannot drift from what is actually enforced.
func (c Config) LockingAnything() bool {
	for _, k := range ChromiumKinds {
		if len(chromiumForcelistValues(c.Targets(k))) > 0 {
			return true
		}
	}
	return len(configuredFirefox(c.Targets(Firefox))) > 0
}

// LookupKnob resolves a knob id, accepting the underscored spelling too since
// that is how the config's field names read.
func LookupKnob(id string) (Knob, bool) {
	id = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(id, "_", "-")))
	for _, k := range Knobs {
		if k.ID == id {
			return k, true
		}
	}
	return Knob{}, false
}

// KnobIDs lists every knob id, for error messages that have to name the choices.
func KnobIDs() []string {
	out := make([]string, 0, len(Knobs))
	for _, k := range Knobs {
		out = append(out, k.ID)
	}
	sort.Strings(out)
	return out
}

// NormalizeSafeSearch reduces what a person would type to one of the three
// levels, returning "" for off. An unrecognized level is an error rather than a
// silent fallback: "safe-search on" quietly meaning nothing would be a setting
// somebody believed in and did not have.
func NormalizeSafeSearch(s string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "", SafeSearchOff:
		return "", nil
	case SafeSearchModerate:
		return SafeSearchModerate, nil
	case SafeSearchStrict, "on", "true", "yes":
		// "on" resolves to strict deliberately. Somebody turning SafeSearch on
		// without saying how much means as much as there is; picking moderate for
		// them would be choosing the weaker reading of an instruction that did not
		// express one.
		return SafeSearchStrict, nil
	default:
		return "", fmt.Errorf("unknown SafeSearch level %q; use moderate, strict or off", s)
	}
}

// Hardened returns the hardening the config asks for, with a nil pointer and an
// unrecognized level both reading as "not managed". Every caller wants a value it
// can ask questions of, so the nil check lives here once.
func (c Config) Hardened() Hardening {
	if c.Hardening == nil {
		return Hardening{}
	}
	h := *c.Hardening
	h.SafeSearch, _ = NormalizeSafeSearch(h.SafeSearch)
	return h
}

// SafeSearchOn reports whether SafeSearch is managed, and at which level.
func (h Hardening) SafeSearchOn() (string, bool) {
	level, err := NormalizeSafeSearch(h.SafeSearch)
	return level, err == nil && level != ""
}

// Any reports whether any knob is on. Nothing is written and nothing is verified
// when this is false, which is what keeps a config that never asked for hardening
// completely untouched.
func (h Hardening) Any() bool {
	_, safe := h.SafeSearchOn()
	return h.PrivateBrowsing || safe
}

// On reports whether one knob is on, by id.
func (h Hardening) On(id string) bool {
	switch id {
	case KnobPrivateBrowsing:
		return h.PrivateBrowsing
	case KnobSafeSearch:
		_, on := h.SafeSearchOn()
		return on
	}
	return false
}

// Describe renders one knob's current setting for display. SafeSearch shows its
// level rather than "on", because which level is in force is the part a reader
// cannot guess.
func (h Hardening) Describe(id string) string {
	switch id {
	case KnobPrivateBrowsing:
		if h.PrivateBrowsing {
			return "blocked"
		}
	case KnobSafeSearch:
		if level, on := h.SafeSearchOn(); on {
			return level
		}
	}
	return "off"
}

// safeSearchRank orders the levels so a change between them can be called
// stronger or weaker. Off is zero, which is what makes turning the knob on
// strictly a strengthening.
func safeSearchRank(level string) int {
	switch level {
	case SafeSearchModerate:
		return 1
	case SafeSearchStrict:
		return 2
	}
	return 0
}

// HardenWeakens reports whether turning a knob on with this level would make
// protection weaker rather than stronger - which decides the gate, exactly as
// Block.Narrows does for a schedule or a limit.
//
// Everywhere else in the guard, adding a rule can only strengthen, so `harden`
// costs admin and nothing more. SafeSearch is the one exception: it has two
// on-states, and `harden safe-search -level moderate` on a machine already set to
// strict is a request to filter less. Without this, that would be the one way to
// weaken protection without the password - the same hole that made `add-block`
// with a window password-gated.
//
// private-browsing has no such case: it is on or off, and on is stronger. Turning
// anything off is `unharden`, which takes the password already.
func (c Config) HardenWeakens(id, level string) bool {
	knob, ok := LookupKnob(id)
	if !ok || knob.ID != KnobSafeSearch {
		return false
	}
	cur, on := c.Hardened().SafeSearchOn()
	if !on {
		return false
	}
	want, err := NormalizeSafeSearch(level)
	if err != nil {
		return false // refused by SetKnob; not a weakening to gate
	}
	if want == "" {
		want = SafeSearchStrict
	}
	return safeSearchRank(want) < safeSearchRank(cur)
}

// SetKnob turns one knob on or off, reporting whether anything changed. level is
// used only by safe-search, where it selects moderate or strict; an empty level
// when turning it on means strict, per NormalizeSafeSearch.
//
// The Hardening pointer is allocated on first use and dropped again when the last
// knob goes off, so a config that never hardens anything - or that hardened
// something and then stopped - encodes byte-identically to one written before this
// existed. Config.Canonical is what the trusted copy is compared on, so that is
// not cosmetic.
//
// It is also never written through in place, always replaced. ActiveAtWith copies
// the Config by assignment, which shares this pointer with the resolved config it
// returns; mutating the pointee here would reach through that copy.
func (c *Config) SetKnob(id string, on bool, level string) (bool, error) {
	knob, ok := LookupKnob(id)
	if !ok {
		return false, fmt.Errorf("unknown setting %q; use %s", id, strings.Join(KnobIDs(), " or "))
	}
	want := Hardening{}
	if c.Hardening != nil {
		want = *c.Hardening
	}
	switch knob.ID {
	case KnobPrivateBrowsing:
		if strings.TrimSpace(level) != "" {
			return false, fmt.Errorf("%s takes no level", knob.ID)
		}
		want.PrivateBrowsing = on
	case KnobSafeSearch:
		if !on {
			if strings.TrimSpace(level) != "" {
				return false, fmt.Errorf("a level makes no sense when turning %s off", knob.ID)
			}
			want.SafeSearch = ""
			break
		}
		norm, err := NormalizeSafeSearch(level)
		if err != nil {
			return false, err
		}
		if norm == "" {
			norm = SafeSearchStrict
		}
		want.SafeSearch = norm
	}

	before := c.Hardened()
	// Normalizing before storing has one side effect worth naming: a level already
	// in the config that does not parse is dropped, even by a change to the other
	// knob. That is the right way round. Hardened() already reads such a level as
	// off and the guard enforces nothing for it, so dropping it makes the file agree
	// with what is actually enforced - the same principle the trusted-config
	// reconcile works on. The alternative is that Validate keeps refusing an
	// unrelated strengthening until the file is hand-fixed.
	wantLevel, _ := NormalizeSafeSearch(want.SafeSearch)
	if want.PrivateBrowsing == before.PrivateBrowsing && wantLevel == before.SafeSearch {
		return false, nil
	}
	want.SafeSearch = wantLevel
	if !want.Any() {
		c.Hardening = nil
		return true, nil
	}
	c.Hardening = &want
	return true, nil
}

// validateHardening rejects a level the guard would otherwise have to guess at.
// Called from Config.Validate, so a hand-edited config is refused at load rather
// than enforcing something its author did not write.
func (c Config) validateHardening() error {
	if c.Hardening == nil {
		return nil
	}
	if _, err := NormalizeSafeSearch(c.Hardening.SafeSearch); err != nil {
		return fmt.Errorf("hardening: %w", err)
	}
	return nil
}
