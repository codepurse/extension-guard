package main

import (
	"fmt"
	"time"

	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/usage"
)

// This file holds `guard limits`, which answers "how much have I got left today".
//
// It needs no config change, no admin and no password, for the same reason
// `guard activity` does not: the person the limit applies to has to be able to see
// where they stand. A budget you can only discover by hitting it is not a limit, it
// is a trap, and one that would make people stop trusting the number. See
// internal/usage for why the ledger is world-readable.

// limitsCmd prints each limited block with what it allows and what is left.
func limitsCmd(cfg policy.Config) {
	now := time.Now()
	limitsAt(cfg, now, cfg.SpentAt(now))
}

// limitsAt is the listing for a given moment and set of spent budgets - the same
// split, and for the same reason, as blocksAt.
func limitsAt(cfg policy.Config, now time.Time, spent policy.Spent) {
	limited := cfg.LimitedBlocks()
	if len(limited) == 0 {
		fmt.Println("no daily time limits configured")
		fmt.Println("(add one with `guard -apps steam.exe -limit 45m add-block games`)")
		return
	}

	fmt.Printf("  %-14s %-22s %-10s %-10s %s\n", "block", "governs", "allowed", "used", "state")
	for _, b := range limited {
		limit, _ := b.LimitFor()
		state := "available"
		switch {
		case spent.Unreadable:
			state = "counted as used up"
		case b.Exhausted(spent):
			state = "used up - blocked"
		case !b.InWindow(now):
			// The budget is not being spent right now and cannot be: the block's
			// windows say it does not apply at this hour.
			state = "out of window"
		}
		used, allowed := "?", policy.HumanDuration(limit)
		if !spent.Unreadable {
			used = policy.HumanDuration(spent.On(b.ID))
		}
		fmt.Printf("  %-14s %-22s %-10s %-10s %s\n", b.ID, b.GovernedSummary(), allowed, used, state)
	}

	resetAt := cfg.ResetAt
	if resetAt == "" {
		resetAt = policy.DefaultResetAt
	}
	fmt.Printf("\n(the day rolls over at %s; time counts while an application is running, not only while you are looking at it)\n", resetAt)
	if spent.Unreadable {
		fmt.Printf("warning: the usage record at %s could not be read, so every limit counts as used up\n", usage.Path())
		fmt.Println("(the guard rewrites it from its own running count within half a minute; if it has to be")
		fmt.Println(" restarted first, today's counts start again from zero and the activity log says so)")
		return
	}
	fmt.Printf("(counted in %s)\n", usage.Path())
}
