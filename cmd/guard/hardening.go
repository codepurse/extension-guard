package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/codepurse/extension-guard/internal/activity"
	"github.com/codepurse/extension-guard/internal/enforce"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
)

// The commands for the hardened browser settings. The gate is the one every other
// rule in the guard uses, and it lands the usual way round here: turning a setting
// on only strengthens protection, so it costs admin and nothing more, while turning
// one off weakens it and takes the password. Reading the state needs neither, like
// `guard activity` and `guard browsers` - a gap only the parent can see is one the
// household argues about instead of closing.

// hardeningCmd lists each setting, whether it is on, and where it does not reach.
// Read-only and admin-free.
func hardeningCmd(cfg policy.Config) {
	h := cfg.Hardened()

	fmt.Printf("  %-20s %-10s %s\n", "setting", "state", "what it covers")
	for _, knob := range policy.Knobs {
		where := browsersFor(knob.ID)
		fmt.Printf("  %-20s %-10s %s\n", knob.ID, h.Describe(knob.ID), where)
	}

	for _, gap := range h.Gaps() {
		fmt.Printf("\nnote: %s\n", gap)
	}

	// The warning, and the reason this command exists at all. It is printed whether
	// or not anything is hardened, because the case that matters is the machine
	// where nobody has turned this on yet - see policy.Config.PrivateBrowsingOpen.
	if w := privateBrowsingWarning(cfg); w != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", w)
		return
	}
	if !h.Any() {
		fmt.Println("\nnothing is hardened; turn a setting on with `guard harden private-browsing`")
	}
}

// hardenCmd turns one setting on and enforces it immediately. Admin, but no
// password: it only adds protection, the same gate as block-domain and
// enable-extension.
//
// The one exception is a SafeSearch level going down. `harden safe-search -level
// moderate` on a machine already set to strict asks for less filtering, not more,
// so it takes the password like unharden does - see policy.Config.HardenWeakens,
// which is the single place that decides.
func hardenCmd(cfg policy.Config, cfgPath, what, level, password string) {
	if strings.TrimSpace(what) == "" {
		fmt.Fprintf(os.Stderr, "error: setting required, e.g. `guard harden %s`\n", policy.KnobPrivateBrowsing)
		os.Exit(2)
	}
	knob, ok := policy.LookupKnob(what)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unknown setting %q; use %s\n", what, strings.Join(policy.KnobIDs(), " or "))
		os.Exit(2)
	}
	if cfg.HardenWeakens(knob.ID, level) && !scm.IsPaused() {
		requirePassword(password, "filtering less than "+knob.ID+" currently does")
	}
	changed, err := cfg.SetKnob(knob.ID, true, level)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if !changed {
		fmt.Printf("%s is already %s\n", knob.ID, cfg.Hardened().Describe(knob.ID))
		return
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	state := cfg.Hardened().Describe(knob.ID)
	activity.Record(activity.Event{Kind: activity.HardeningEnabled, Target: knob.ID, Detail: state})
	fmt.Printf("%s: %s (%s)\n", knob.ID, state, browsersFor(knob.ID))
	fmt.Printf("\n%s\n", knob.Note)
	printRestartNote()
}

// unhardenCmd turns one setting off, which weakens protection, so it takes the
// password - except while protection is in the authorized paused state, where
// there is nothing being enforced to bypass. Mirrors unblock-domain.
func unhardenCmd(cfg policy.Config, cfgPath, what, password string) {
	if strings.TrimSpace(what) == "" {
		fmt.Fprintf(os.Stderr, "error: setting required, e.g. `guard unharden %s`\n", policy.KnobPrivateBrowsing)
		os.Exit(2)
	}
	knob, ok := policy.LookupKnob(what)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unknown setting %q; use %s\n", what, strings.Join(policy.KnobIDs(), " or "))
		os.Exit(2)
	}
	if !cfg.Hardened().On(knob.ID) {
		fmt.Printf("%s is already off\n", knob.ID)
		return
	}
	if !scm.IsPaused() {
		requirePassword(password, "turning off "+knob.ID)
	}
	if _, err := cfg.SetKnob(knob.ID, false, ""); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	activity.Record(activity.Event{Kind: activity.HardeningDisabled, Target: knob.ID})
	fmt.Printf("%s: off\n", knob.ID)
	if knob.ID == policy.KnobPrivateBrowsing {
		fmt.Println("(private windows work again, and in Chrome, Edge and Brave a locked extension")
		fmt.Println("does not run in one)")
	}
	printRestartNote()
}

// browsersFor names the browsers a setting can actually be enforced in, so the
// listing does not have to be read alongside the documentation to know where a row
// applies.
func browsersFor(knobID string) string {
	var in []string
	for _, k := range policy.AllKinds() {
		if policy.KnobSupported(knobID, k) {
			in = append(in, string(k))
		}
	}
	return strings.Join(in, ", ")
}

// privateBrowsingWarning is the hole reported in words. It mirrors
// unmanagedBrowserWarning: a table saying every browser is locked, printed on a
// machine where Ctrl+Shift+N opens a window none of the locked extensions run in,
// is a true statement doing the work of a false one.
func privateBrowsingWarning(cfg policy.Config) string {
	if !cfg.PrivateBrowsingOpen() {
		return ""
	}
	return "warning: private browsing is available in Chrome, Edge or Brave, and a force-installed\n" +
		"extension does not run in an Incognito or guest window there - so every extension this\n" +
		"guard locks can be sidestepped with Ctrl+Shift+N. Close it with\n" +
		"`guard harden " + policy.KnobPrivateBrowsing + "`, or in Edge with `guard harden " +
		policy.KnobPrivateExtensions + "`,\nwhich keeps InPrivate and refuses to navigate in it " +
		"until the extension is allowed there.\n" +
		"(Firefox and Zen are not part of this: the add-on is force-enabled in their private windows.)"
}
