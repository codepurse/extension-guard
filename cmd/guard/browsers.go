package main

import (
	"fmt"
	"strings"

	"github.com/codepurse/extension-guard/internal/policy"
)

// This file holds `guard browsers`, which is a report and nothing else: it reads
// the machine, writes nothing, and needs neither admin nor the password. Like
// `guard activity`, being readable by everyone it concerns is the point - a gap
// only the parent can see is a gap the household argues about instead of closing.
//
// It answers a question the rest of the CLI cannot. `guard verify` says the four
// supported browsers are locked, and that is true and still leaves Opera sitting
// in the Start menu filtering nothing. See internal/policy/browsers.go.

// The states a browser can be in, worst first. A browser is either filtered by
// the policies the guard writes, or blocked so it cannot run, or a way around
// everything.
const (
	browserReachable = "reachable" // unmanaged, nothing blocking it: the finding
	browserIdle      = "idle"      // unmanaged, on the block list, outside its window
	browserBlocked   = "blocked"   // unmanaged, blocked around the clock
	browserFiltered  = "filtered"  // one of the four the guard writes policy for
	browserGone      = "gone"      // registered, but the executable is not there
)

// browsersCmd lists every browser on this machine and what the guard can do
// about each.
func browsersCmd(cfg policy.Config) {
	if !policy.BrowserScanSupported() {
		fmt.Println("listing the installed browsers is not implemented on this platform")
		fmt.Println("(the guard still locks the browsers it manages; it just cannot tell you what else is here)")
		return
	}

	found := policy.RegisteredBrowsers()
	if len(found) == 0 {
		fmt.Println("no registered browsers found on this machine")
		fmt.Println("(a browser that registers nothing - an unpacked portable copy - would not appear here either)")
		return
	}

	// The list as written decides "blocked"; the schedule-resolved config decides
	// whether it is blocked at this moment. Both are shown, because a browser
	// blocked only on weekday afternoons is genuinely on the list and genuinely
	// reachable right now, and one badge cannot say both.
	active := cfg

	fmt.Printf("  %-34s %-10s %s\n", "browser", "state", "executable")
	reachable, gone := 0, 0
	for _, b := range found {
		state := browserFiltered
		switch {
		case b.Managed() && active.BlocksBrowser(b):
			// Filtered and blocked at once, which a Firefox fork can now be: the
			// guard writes policy it reads, and the browsers category also names it.
			// Blocked is the truthful word for it - the window closes a second after
			// it opens, and calling that "filtered" would describe a browser the user
			// can still use.
			state = browserBlocked
		case b.Managed():
			// A managed browser whose file is gone was uninstalled and left its
			// registration behind. There is nothing to say about it: the guard's
			// policy is still written, and applies again the day it comes back.
		case b.Missing:
			// Reported before the block state, because "the file this names is not
			// there" is the more important fact about it - and because calling it
			// reachable or blocked would both be claims about a file that is absent.
			state = browserGone
			gone++
		case active.BlocksBrowser(b):
			state = browserBlocked
		case cfg.BlocksBrowser(b):
			state = browserIdle
		default:
			state = browserReachable
			reachable++
		}
		exe := b.Exe
		if strings.TrimSpace(exe) == "" {
			exe = "(the registration names no executable)"
		}
		fmt.Printf("  %-34s %-10s %s\n", truncate(b.Label(), 34), state, exe)
	}

	fmt.Println()
	fmt.Println("filtered   the guard writes policy this browser reads, so the locked extensions")
	fmt.Println("           and the blocked sites apply inside it")
	fmt.Println("blocked    the guard cannot filter it, so it is on the block list and will not run")
	fmt.Println("idle       on the block list, but outside its block's window right now")
	fmt.Println("reachable  the guard neither filters nor blocks it - every blocked site is")
	fmt.Println("           reachable through it, and none of the locked extensions are loaded")
	if gone > 0 {
		fmt.Println("gone       registered as a browser, but the executable it names is not there:")
		fmt.Println("           either it was uninstalled, or the file was renamed")
	}

	if gone > 0 {
		fmt.Println()
		fmt.Println("a renamed executable is the one bypass the guard does not correct, so a")
		fmt.Println("registration pointing at a file that is not there is worth a look. Rules")
		fmt.Println("naming a bare executable also match the name compiled into the program, so")
		fmt.Println("a plain rename does not get past them - a repacked binary can.")
	}

	if reachable == 0 {
		fmt.Println()
		fmt.Println("every browser here is either filtered or blocked")
		return
	}

	fmt.Println()
	if reachable == 1 {
		fmt.Println("1 browser here is outside everything the guard enforces")
	} else {
		fmt.Printf("%d browsers here are outside everything the guard enforces\n", reachable)
	}
	fmt.Println("block the ones the guard knows by name with `guard block-category browsers`")
	fmt.Println("block anything that list misses by its path: `guard block-app \"<executable>\"`")
}

// unmanagedBrowserWarning is the one line printed by `guard verify` when a
// browser is reachable, and by nothing else. It is deliberately terse: verify's
// job is the enforcement table, and this is a pointer at `guard browsers` rather
// than a second report competing with it.
//
// It returns "" when there is nothing to say, so a caller can print it or not
// without knowing any of the above. On a platform that cannot scan it also
// returns "" - saying nothing is right when the alternative is either a false
// all-clear or a warning about every machine the guard has never looked at.
func unmanagedBrowserWarning(cfg policy.Config) string {
	if !policy.BrowserScanSupported() {
		return ""
	}
	return browserWarningFor(cfg.UnblockedBrowsers(), cfg.VanishedBrowsers())
}

// browserWarningFor is the wording, split from the scan so a test can hand it one
// browser and two and check both read as English. The plural is not a nicety
// here: this is the only warning printed by a command whose whole output is a
// table saying everything is fine, and one that reads as broken invites the
// reader to treat it as noise.
//
// Two findings, each its own line, because they call for different things. A
// reachable browser is a gap to close. A blocked browser whose file has vanished
// is something to go and look at, and may be nothing at all.
func browserWarningFor(open, vanished []policy.InstalledBrowser) string {
	var lines []string
	if len(open) > 0 {
		through := "it"
		if len(open) != 1 {
			through = "them"
		}
		lines = append(lines, fmt.Sprintf(
			"warning: the guard cannot filter and is not blocking %s on this machine: %s\n"+
				"(every blocked site is reachable through %s - see `guard browsers`)",
			countBrowsers(len(open)), strings.Join(labelsOf(open), ", "), through))
	}
	if len(vanished) > 0 {
		// Written out per case rather than assembled from a pronoun and a verb.
		// Three words have to agree here, and every attempt to do that by
		// substitution produces something like "the executable were named".
		phrase := "1 browser is on the block list, and the executable it named is gone"
		if len(vanished) != 1 {
			phrase = fmt.Sprintf(
				"%d browsers are on the block list, and the executables they named are gone",
				len(vanished))
		}
		lines = append(lines, fmt.Sprintf(
			"warning: %s: %s\n"+
				"(uninstalled, or renamed to get around the block - see `guard browsers`)",
			phrase, strings.Join(labelsOf(vanished), ", ")))
	}
	return strings.Join(lines, "\n\n")
}

func labelsOf(list []policy.InstalledBrowser) []string {
	out := make([]string, 0, len(list))
	for _, b := range list {
		out = append(out, b.Label())
	}
	return out
}

// countBrowsers writes the count as a noun phrase, because "1 browsers" in a
// warning about protection not applying reads as carelessness about the rest of
// it.
func countBrowsers(n int) string {
	if n == 1 {
		return "1 browser"
	}
	return fmt.Sprintf("%d browsers", n)
}

// truncate keeps a name inside its column. A browser registration can carry a
// long name, and one that wraps pushes the executable onto its own line - which
// is the column a person is reading this table for.
//
// It counts runes rather than bytes because a registered browser name is not
// always ASCII: Maxthon registers itself in Chinese on a Chinese install, and
// cutting that mid-character would print replacement characters where a browser
// name belongs. The column will still be a little wide for a name of double-width
// characters, which is a terminal problem this is not going to solve; producing
// invalid text is a problem it can avoid outright.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}
