package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/usage"
)

// This file holds `guard usage`: how long each blocked application was actually
// running, today and over the past days.
//
// Like `guard limits` and `guard activity` it needs no admin and no password. The
// record is about the person using the machine, and a record they cannot read is
// one they can only argue with. See internal/usage for why the ledger is
// world-readable, and internal/policy/stats.go for what is and is not counted.

// defaultUsageDays is the span the bare command covers. A week is the unit people
// actually think in, and it fits on a screen; the ledger keeps far more, which is
// what the positional argument reaches.
const defaultUsageDays = 7

// usageBarWidth is how wide the per-day bar can get. Narrow enough that a 90-column
// terminal holds the label, the duration and the bar.
const usageBarWidth = 28

// usageCmd prints the per-application record for the last n days.
func usageCmd(cfg policy.Config, arg string) {
	days := defaultUsageDays
	if s := strings.TrimSpace(arg); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "error: %q is not a number of days, e.g. `guard usage 30`\n", arg)
			os.Exit(2)
		}
		days = n
	}
	if days > usage.KeepDays {
		// Say so rather than silently showing less than was asked for: a total that
		// quietly covers a different span than the one requested is worse than a
		// refusal, because it looks like an answer.
		fmt.Printf("(the record keeps %d days, so that is what this covers)\n\n", usage.KeepDays)
		days = usage.KeepDays
	}

	rep := cfg.UsageStats(time.Now(), days)
	if !rep.Measured {
		fmt.Println("no applications are blocked, so there is nothing being measured")
		fmt.Println("(add one with `guard block-app steam.exe`; sites and extensions cannot be measured - see `guard limits`)")
		return
	}
	if rep.Unreadable {
		fmt.Fprintf(os.Stderr, "warning: the usage record at %s could not be read\n", usage.Path())
		fmt.Fprintln(os.Stderr, "(the guard rewrites it from its own running count within half a minute)")
		return
	}
	if len(rep.Rows) == 0 {
		fmt.Printf("nothing recorded in the last %s\n", plural(days, "day"))
		fmt.Println("(time is counted while a blocked application is running; one that never starts records nothing)")
		return
	}

	fmt.Printf("  %-28s %-10s %s\n", "application", "today", plural(days, "day"))
	for _, r := range rep.Rows {
		label := r.Label
		if r.Gone {
			label += " *"
		}
		fmt.Printf("  %-28s %-10s %s\n", truncate(label, 28), policy.HumanDuration(r.Today), policy.HumanDuration(r.Total))
	}

	// Both totals, because they answer different questions and neither is the
	// obvious one on its own - see policy.UsageReport.
	fmt.Printf("\n  %-28s %-10s %s\n", "time with any of them open",
		policy.HumanDuration(rep.TodaySpan), policy.HumanDuration(rep.TotalSpan))

	printUsageDays(rep)

	if anyGone(rep) {
		fmt.Println("\n* no longer on the block list; the time it was used is kept")
	}
	fmt.Println("\n(counted while an application is running, not only while you are looking at it,")
	fmt.Println(" and it keeps counting while protection is paused)")
	fmt.Printf("(recorded in %s)\n", usage.Path())
}

// printUsageDays draws one line per day, oldest last, so a week reads top to bottom
// as most recent first - the same order `guard activity` uses.
//
// The bar is scaled to the busiest day in the span rather than to a fixed hour. A
// fixed scale makes a quiet week look like a broken feature, and the number is
// printed next to it either way.
func printUsageDays(rep policy.UsageReport) {
	var peak time.Duration
	for _, d := range rep.ByDay {
		if d > peak {
			peak = d
		}
	}
	if peak == 0 {
		return
	}
	fmt.Println()
	for i, day := range rep.Days {
		spent := rep.ByDay[i]
		width := int(int64(spent) * usageBarWidth / int64(peak))
		if width == 0 && spent > 0 {
			width = 1 // a day with any use at all must not read as an empty one
		}
		fmt.Printf("  %-11s %-10s %s\n", day, policy.HumanDuration(spent), strings.Repeat("#", width))
	}
}

func anyGone(rep policy.UsageReport) bool {
	for _, r := range rep.Rows {
		if r.Gone {
			return true
		}
	}
	return false
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}
