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
// How wide that hole is depends on the browser, and the answer has changed:
//
//   - The Firefox family no longer has it. Mozilla added private_browsing to
//     ExtensionSettings in Firefox 136 and ESR 128.8, so the guard force-enables
//     the add-on in private windows outright, with no switch and nothing for the
//     user to agree to. That is written by the extension enforcer next to
//     installation_mode, not from here, because it takes no feature away and so
//     is part of force-installing rather than a setting to opt into.
//   - Edge can be told to refuse InPrivate navigation until the user allows the
//     extension there - MandatoryExtensionsForInPrivateNavigation, Edge 139. That
//     keeps InPrivate working and filtered instead of removing it, so it is the
//     softer of the two remedies and gets its own knob.
//   - Chrome and Brave still have it whole. Google's equivalent policy exists but
//     is declared for ChromeOS only, so writing it on a desktop would be the
//     exact failure gecko.go warns about: a policy that verifies perfectly and
//     enforces nothing. Turning Incognito off remains the only lever there.
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
	// PrivateExtensions requires the locked extensions to be allowed in a private
	// window before that window will navigate, rather than removing private
	// windows. Edge only - see KnobPrivateExtensions.
	PrivateExtensions bool `json:"privateExtensions,omitempty"`
}

// Hardening knob ids, as the CLI and the status window name them.
const (
	KnobPrivateBrowsing   = "private-browsing"
	KnobPrivateExtensions = "private-extensions"
)

// Knob is one hardening switch: what it is called, and what it does and does not
// cover. The note is printed when it is turned on, for the reason Category.Note
// exists - a switch that promises more than it delivers is worse than one that
// says where it stops.
type Knob struct {
	ID    string
	Label string
	Note  string
	// Gap replaces the reason Gaps() gives for the browsers a knob cannot reach.
	// The default sentence - "there is no policy for it" - is true of every knob
	// here but one, and saying it of a browser that needs no policy because the
	// guard already covers it another way would send a reader looking for a hole
	// that is not there.
	Gap string
}

// Knobs is every hardening switch, in the order they are listed.
var Knobs = []Knob{
	{
		ID:    KnobPrivateBrowsing,
		Label: "Private browsing and guest profiles",
		Note: "This is the bypass that makes a locked extension optional: an extension cannot be " +
			"force-installed into a Chrome, Edge or Brave Incognito window, and a guest profile " +
			"carries no extensions at all, so every filter the guard installs in those browsers is " +
			"one keystroke from being off. Turning this on disables private windows and guest " +
			"profiles in Chrome, Edge, Brave, Firefox and Zen. The Firefox family is the one place " +
			"this is no longer the only answer - the guard force-enables the add-on in private " +
			"windows there, so Firefox and Zen are already covered whether or not this is on, and " +
			"turning it on removes the window rather than closing a hole. In Edge, `" +
			KnobPrivateExtensions + "` is the narrower alternative. It does not cover a browser the " +
			"guard writes no policy for - run `guard browsers` for those - and it leaves ordinary " +
			"named profiles alone, which need no blocking because a machine-wide force-install " +
			"reaches all of them.",
	},
	{
		ID:    KnobPrivateExtensions,
		Label: "Extensions required in private windows",
		Gap:   "see the note on this setting for what covers each of them instead",
		Note: "The same hole as `" + KnobPrivateBrowsing + "`, closed without taking the window " +
			"away: InPrivate keeps working, but refuses to navigate until the locked extensions are " +
			"allowed to run in it. The user is the one who allows them, on Edge's own extensions " +
			"page, and until they do InPrivate opens and goes nowhere - so it cannot be used as a " +
			"way past the filters, and it is not removed either. Prefer it to `" +
			KnobPrivateBrowsing + "` when InPrivate is something the person here has a real use for; " +
			"prefer `" + KnobPrivateBrowsing + "` when it is not, because that one needs nobody's " +
			"cooperation. Turning both on is not an error and not useful: with private browsing " +
			"blocked there is no InPrivate window left for this to hold up. " +
			"Where it applies is narrow and worth reading twice. Edge only, and only Edge 139 and " +
			"newer - an older Edge ignores it and InPrivate stays open. Chrome and Brave are not " +
			"covered: Google's equivalent policy is declared for ChromeOS and not for desktop, and " +
			"writing it here would report a setting that enforces nothing, so the guard does not " +
			"write it. Firefox and Zen need nothing - the add-on is force-enabled in their private " +
			"windows already. So on a machine where Chrome is the browser that matters, this " +
			"setting changes nothing and `" + KnobPrivateBrowsing + "` is still the only answer.",
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
// dns-filter is the one knob with no gap. Chromium has taken DnsOverHttpsMode
// and DnsOverHttpsTemplates since Chrome 78 and Edge 83, and Mozilla's policy
// engine has DNSOverHTTPS since Firefox 63 - so unlike safe-search, the Gecko
// half is not a hole to be reported but a policy that is actually written. The
// one version-dependent piece is Mozilla's Fallback, which arrived in Firefox
// 124: on an older build the other three values still apply and Firefox falls
// back to the system resolver on error, which is a weaker promise than the
// Chromium half makes. That is a fact about old Firefox and not something the
// guard can close, so the knob's own note says it rather than knobSupport
// pretending the browser is unsupported.
var knobSupport = map[string][]Kind{
	KnobPrivateBrowsing: {Chrome, Edge, Brave, Firefox, Zen},
	// private-extensions is Edge's alone, and both halves of that are facts about
	// the browsers rather than about this program. Chrome and Brave: Chromium
	// declares MandatoryExtensionsForIncognitoNavigation for ChromeOS only, so on a
	// desktop it is a policy that would be written, verified and ignored. Firefox
	// and Zen: nothing to require, because the extension enforcer force-enables the
	// add-on in their private windows outright.
	KnobPrivateExtensions: {Edge},
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

// mandatoryPrivateIDs is the extension ids this browser should require in a
// private window - which is every extension it is actually force-installing, and
// nothing at all for a browser that cannot be told to require anything.
//
// It reads the same targets the forcelist writer does, through the same "is this
// target applyable" check, so the two cannot disagree about which extensions
// exist. Requiring an id that is not being force-installed would be worse than
// pointless: Edge blocks InPrivate navigation when a required extension is not
// installed, so a placeholder left in the config would turn into an InPrivate
// window that can never work, no matter what the user allows.
func mandatoryPrivateIDs(cfg Config, k Kind) []string {
	if !KnobSupported(KnobPrivateExtensions, k) {
		return nil
	}
	out := make([]string, 0, 2)
	for _, t := range cfg.Targets(k) {
		if _, err := chromiumForcelistValue(t); err != nil {
			continue
		}
		out = append(out, t.ExtensionID)
	}
	return out
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
			reason := knob.Gap
			if reason == "" {
				reason = "there is no policy for it"
			}
			out = append(out, fmt.Sprintf("%s is not enforced in %s - %s",
				knob.ID, strings.Join(missing, ", "), reason))
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
// It is also asked per browser rather than once, which it did not have to be
// until the answer stopped being the same everywhere. A machine locking only
// Firefox has no hole to warn about - the add-on runs in its private windows -
// and warning anyway would be the always-on warning this comment refuses.
func (c Config) PrivateBrowsingOpen() bool {
	h := c.Hardened()
	if h.PrivateBrowsing {
		return false
	}
	for _, k := range ChromiumKinds {
		if len(chromiumForcelistValues(c.Targets(k))) == 0 {
			continue
		}
		if k == Edge && h.PrivateExtensions {
			continue // InPrivate will not navigate without the extension
		}
		return true
	}
	return false
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

// Hardened returns the hardening the config asks for, with a nil pointer and an
// unrecognized level both reading as "not managed". Every caller wants a value it
// can ask questions of, so the nil check lives here once.
func (c Config) Hardened() Hardening {
	if c.Hardening == nil {
		return Hardening{}
	}
	h := *c.Hardening
	return h
}

// Any reports whether any knob is on. Nothing is written and nothing is verified
// when this is false, which is what keeps a config that never asked for hardening
// completely untouched.
func (h Hardening) Any() bool {
	return h.PrivateBrowsing || h.PrivateExtensions
}

// On reports whether one knob is on, by id.
func (h Hardening) On(id string) bool {
	switch id {
	case KnobPrivateBrowsing:
		return h.PrivateBrowsing
	case KnobPrivateExtensions:
		return h.PrivateExtensions
	}
	return false
}

// Describe renders one knob's current setting for display, in the word that says
// what it does rather than a bare "on".
func (h Hardening) Describe(id string) string {
	switch id {
	case KnobPrivateBrowsing:
		if h.PrivateBrowsing {
			return "blocked"
		}
	case KnobPrivateExtensions:
		// "required" rather than "on", because which of the two private-window
		// settings is in force is exactly what a reader needs to tell apart: this
		// one leaves the window open and holds it up, the other removes it.
		if h.PrivateExtensions {
			return "required"
		}
	}
	return "off"
}

// SetKnob turns one knob on or off, reporting whether anything changed.
//
// The Hardening pointer is allocated on first use and dropped again when the last
// knob goes off, so a config that never hardens anything - or that hardened
// something and then stopped - encodes byte-identically to one written before this
// existed. Config.Canonical is what the trusted copy is compared on, so that is
// not cosmetic.
//
// It is also never written through in place, always replaced: a Config is copied
// by assignment in several places, which shares this pointer, and mutating the
// pointee would reach through those copies.
func (c *Config) SetKnob(id string, on bool) (bool, error) {
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
		want.PrivateBrowsing = on
	case KnobPrivateExtensions:
		want.PrivateExtensions = on
	}
	before := c.Hardened()
	if want == before {
		return false, nil
	}
	if !want.Any() {
		c.Hardening = nil
		return true, nil
	}
	c.Hardening = &want
	return true, nil
}

// validateHardening checks the hardening section. Both settings are booleans, so
// there is nothing here that can be written wrongly - the function is kept
// because Validate calls it and the next setting added here may not be a
// boolean.
func (c Config) validateHardening() error { return nil }
