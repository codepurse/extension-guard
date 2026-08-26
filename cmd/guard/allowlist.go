package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/codepurse/extension-guard/internal/activity"
	"github.com/codepurse/extension-guard/internal/enforce"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
)

// The commands for the allowlist mode: block the whole web, name the exceptions.
//
// The gate here is the inverse of the block list's in both halves, which is worth
// keeping in mind while reading: turning the mode on strengthens (free), turning it
// off weakens (password); *allowing* a site weakens (password), *un-allowing* one
// strengthens (free). policy.AllowNarrows is the one place that decides, and the
// elevated guard re-checks it, so the status window cannot skip it.

// allowedCmd lists the mode, its timetable, and the sites it lets through.
// Read-only and admin-free, like `guard domains`.
func allowedCmd(cfg policy.Config) {
	a := cfg.Allowing()
	now := time.Now()

	state := "off"
	switch {
	case !a.On:
	case cfg.AllowlistOn(now):
		state = "on"
	default:
		// On, but its window is shut. That is not the mode being off, and saying "off"
		// would read as "somebody turned this off" - the same distinction a domain
		// outside its block's window gets from the "idle" state.
		state = "waiting"
	}
	fmt.Printf("  allowed sites only: %s (%s)\n", state, a.ScheduleSummary())

	sites := a.AllowedSites()
	if len(sites) == 0 {
		fmt.Println("\nnothing is on the allowlist")
		if a.On {
			// Worth saying out loud rather than leaving to be discovered: this is the
			// state where every page in every managed browser is refused.
			fmt.Println("(so every site is blocked in every browser the guard filters - that is what this mode means)")
		}
		fmt.Println("(add one with `guard allow wikipedia.org`)")
		return
	}
	fmt.Printf("\n  %-40s %s\n", "allowed site", "note")
	for _, host := range sites {
		fmt.Printf("  %-40s %s\n", host, "also covers every subdomain")
	}
	if !a.On {
		fmt.Println("\n(the mode is off, so these are not doing anything; turn it on with `guard allow-only on`)")
	}
	printFirefoxNote()
}

// allowOnlyCmd turns the mode on or off. On only strengthens - it blocks the entire
// web - so it costs admin and no password. Off unblocks the entire web, which is the
// largest single weakening in this program, so it takes the password.
func allowOnlyCmd(cfg policy.Config, cfgPath, arg, password string) {
	var on bool
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "on", "true", "yes":
		on = true
	case "off", "false", "no":
		on = false
	default:
		fmt.Fprintln(os.Stderr, "error: say on or off, e.g. `guard allow-only on`")
		os.Exit(2)
	}

	action := policy.AllowActionOn
	if !on {
		action = policy.AllowActionOff
	}
	if policy.AllowNarrows(action) && !scm.IsPaused() {
		requirePassword(password, "turning off allowed-sites-only")
	}
	if !cfg.SetAllowlistOn(on) {
		fmt.Printf("allowed sites only is already %s\n", arg)
		return
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))

	if on {
		activity.Record(activity.Event{Kind: activity.AllowlistOn, Detail: allowSummary(cfg)})
		fmt.Printf("allowed sites only: on (%s)\n", cfg.Allowing().ScheduleSummary())
		sites := cfg.Allowing().AllowedSites()
		if len(sites) == 0 {
			fmt.Println("\nthe allowlist is empty, so every site is now blocked in every browser the guard filters.")
			fmt.Println("add the ones you need with `guard allow <site>` - that needs the password, because it")
			fmt.Println("opens something this mode had closed.")
		} else {
			fmt.Printf("everything is blocked except %s (and their subdomains)\n", strings.Join(sites, ", "))
		}
	} else {
		activity.Record(activity.Event{Kind: activity.AllowlistOff})
		fmt.Println("allowed sites only: off - the web is reachable again, except what is on the block list")
	}
	printUnmanagedAllowNote(cfg)
	printFirefoxNote()
}

// allowCmd puts a site on the allowlist. This *weakens* protection - it opens
// something the mode had closed - so unlike `block-domain` it takes the password.
func allowCmd(cfg policy.Config, cfgPath, name, password string) {
	if strings.TrimSpace(name) == "" {
		fmt.Fprintln(os.Stderr, "error: site required, e.g. `guard allow wikipedia.org`")
		os.Exit(2)
	}
	// Only when the mode is on: while it is off the allowlist enforces nothing, so
	// adding to it opens nothing and there is nothing to gate. This is the same
	// reasoning that makes creating a windowless block free.
	if cfg.Allowing().On && !scm.IsPaused() {
		requirePassword(password, "allowing a site through")
	}
	host, changed, err := cfg.AddAllowed(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if !changed {
		fmt.Printf("%s is already allowed\n", host)
		return
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	activity.Record(activity.Event{Kind: activity.SiteAllowed, Target: host})
	fmt.Printf("allowed: %s and every subdomain\n", host)
	if !cfg.Allowing().On {
		fmt.Println("(allowed sites only is off, so this is not letting anything through yet)")
	}
	printFirefoxNote()
}

// unallowCmd takes a site off the allowlist, closing it again. That only
// strengthens, so it needs admin and no password - the mirror of `allow`.
func unallowCmd(cfg policy.Config, cfgPath, name string) {
	if strings.TrimSpace(name) == "" {
		fmt.Fprintln(os.Stderr, "error: site required, e.g. `guard unallow wikipedia.org`")
		os.Exit(2)
	}
	host, removed := cfg.RemoveAllowed(name)
	if !removed {
		fmt.Fprintf(os.Stderr, "error: %s is not on the allowlist\n", host)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	activity.Record(activity.Event{Kind: activity.SiteUnallowed, Target: host})
	fmt.Printf("no longer allowed: %s\n", host)
	printFirefoxNote()
}

// allowSummary describes the mode for the activity record, so a line in the log
// says what was turned on rather than only that something was.
func allowSummary(cfg policy.Config) string {
	a := cfg.Allowing()
	sites := a.AllowedSites()
	if len(sites) == 0 {
		return "every site blocked; the allowlist is empty (" + a.ScheduleSummary() + ")"
	}
	return fmt.Sprintf("everything blocked except %d site(s) (%s)", len(sites), a.ScheduleSummary())
}

// printUnmanagedAllowNote says the thing this mode makes most acute. Blocking every
// site is worth nothing at all through a browser the guard writes no policy for, and
// this is the one feature where that gap goes from a leak to the whole roof.
func printUnmanagedAllowNote(cfg policy.Config) {
	if !cfg.Allowing().On {
		return
	}
	if w := unmanagedBrowserWarning(cfg); w != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", w)
		fmt.Fprintln(os.Stderr, "(this mode blocks every site in the browsers above - and none at all in those)")
	}
}
