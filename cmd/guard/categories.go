package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/codepurse/extension-guard/internal/activity"
	"github.com/codepurse/extension-guard/internal/enforce"
	"github.com/codepurse/extension-guard/internal/policy"
)

// This file holds the commands for the built-in categories - curated sets of
// applications and sites that stand for one kind of distraction. They sit on the
// same gate as block-app and block-domain: adding one only strengthens
// protection, so it costs admin and nothing more. There is no unblock-category,
// deliberately - a category expands into ordinary rules and an ordinary block,
// so lifting it is remove-block and unblock-app, which already take the password
// because they are what weakens.

// categoriesCmd lists what is available and which have been applied. Named with
// an id it lists that category's contents instead. Read-only and admin-free,
// like `apps` and `domains`.
//
// The contents view exists because agreeing to a category is agreeing to
// everything in it at once, and a count is not something a person can consent
// to. Blocking twenty-eight things you have not seen is how a user ends up
// surprised by a block they cannot lift without the password.
func categoriesCmd(cfg policy.Config, id string) {
	if strings.TrimSpace(id) != "" {
		showCategoryCmd(cfg, id)
		return
	}
	fmt.Printf("  %-10s %-19s %-9s %s\n", "id", "name", "state", "covers")
	for _, cid := range policy.CategoryIDs() {
		cat, _ := policy.LookupCategory(cid)
		state := "available"
		if _, ok := cfg.Block(cat.ID); ok {
			state = "blocked"
		}
		fmt.Printf("  %-10s %-19s %-9s %d apps, %d sites\n",
			cat.ID, cat.Label, state, len(cat.Apps), len(cat.Domains))
	}
	fmt.Println()
	fmt.Println("see what one covers with `guard categories social`")
	fmt.Println("block one with `guard block-category social`")
}

// showCategoryCmd lists everything one category covers, marking what the config
// already holds. The two columns answer the two questions a person actually has
// in front of this list: what am I agreeing to, and how much of it is new.
func showCategoryCmd(cfg policy.Config, id string) {
	cat, ok := policy.LookupCategory(id)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: no category %q - want one of %s\n", id, strings.Join(policy.CategoryIDs(), ", "))
		os.Exit(1)
	}
	entries := cfg.CategoryEntries(cat)
	missing := cfg.CategoryMissing(cat)

	fmt.Printf("%s - %d applications and %d sites\n", cat.Label, len(cat.Apps), len(cat.Domains))
	if _, blocked := cfg.Block(cat.ID); blocked {
		fmt.Printf("blocked now, under the block %q\n", cat.ID)
	}
	switch missing {
	case 0:
		fmt.Println("all of it is already in the block list; blocking it again would change nothing")
	case len(entries):
		fmt.Println("none of it is blocked yet")
	default:
		fmt.Printf("%d of these are not blocked yet\n", missing)
	}
	fmt.Println()

	fmt.Printf("  %-30s %-16s %s\n", "entry", "state", "covers")
	for _, e := range entries {
		state := "new"
		if e.Present {
			state = "already blocked"
		}
		fmt.Printf("  %-30s %-16s %s\n", e.Label, state, e.Detail)
	}
	if cat.Note != "" {
		fmt.Printf("\nnote: %s\n", cat.Note)
	}
	if missing > 0 {
		fmt.Printf("\nblock all of it with `guard block-category %s`\n", cat.ID)
	}
}

// blockCategoryCmd expands a category into the config and enforces it. Admin, but
// no password: it adds an always-on block and nothing else, the same trade as
// block-app.
//
// Re-running it tops the category up rather than failing, which is what makes a
// later catalog addition reachable at all - see policy.ApplyCategory.
func blockCategoryCmd(cfg policy.Config, cfgPath, id string) {
	if strings.TrimSpace(id) == "" {
		fmt.Fprintln(os.Stderr, "error: category required, e.g. `guard block-category social`")
		fmt.Fprintln(os.Stderr, "(run `guard categories` to see them)")
		os.Exit(2)
	}
	cat, ok := policy.LookupCategory(id)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: no category %q - want one of %s\n", id, strings.Join(policy.CategoryIDs(), ", "))
		os.Exit(1)
	}

	res, err := cfg.ApplyCategory(cat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	// Validated before anything is written, the same way add-block does it: a
	// category that cannot pass validation should leave the config untouched
	// rather than half applied.
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, "(nothing was changed)")
		os.Exit(1)
	}
	if !res.Changed() {
		fmt.Printf("%s is already blocked in full\n", cat.Label)
		reportSkipped(res)
		return
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	activity.Record(activity.Event{
		Kind:   activity.CategoryBlocked,
		Target: cat.Label,
		Detail: fmt.Sprintf("%d applications, %d sites", len(res.Apps), len(res.Domains)),
	})

	if res.NewBlock {
		fmt.Printf("blocked %s: %d applications and %d sites, around the clock\n",
			cat.Label, len(res.Apps), len(res.Domains))
	} else {
		fmt.Printf("topped up %s: %d new applications and %d new sites\n",
			cat.Label, len(res.Apps), len(res.Domains))
	}
	reportSkipped(res)

	if cat.Note != "" {
		fmt.Printf("\nnote: %s\n", cat.Note)
	}
	fmt.Printf("\nput it on a schedule with `guard -label %q -days mon-fri -from 09:00 -to 17:00 add-block %s`\n", cat.Label, cat.ID)
	fmt.Printf("lock it with `guard -until 7d lock %s`\n", cat.ID)
}

// reportSkipped names what the category could not add. These are not failures -
// an entry already covered by a folder rule is already blocked - but staying
// quiet about them would leave the user believing a count that is not the one
// they got.
func reportSkipped(res policy.CategoryResult) {
	if len(res.Skipped) == 0 {
		return
	}
	fmt.Printf("(%d entries left alone, already covered:)\n", len(res.Skipped))
	for _, s := range res.Skipped {
		fmt.Printf("  %s\n", s)
	}
}
