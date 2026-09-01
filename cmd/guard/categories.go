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
//
// One category, "adult", names no rules at all and only turns browser settings
// on. It has no block, so nothing here can schedule or lock it, and lifting it
// is `guard unharden` rather than remove-block. Category.BlocksAnything is the
// one place that decides which of the two shapes is in hand, and the wording
// below follows it: settings are turned "on", never "blocked".

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
		if cfg.CategoryApplied(cat) {
			state = "blocked"
			if !cat.BlocksAnything() {
				state = "on"
			}
		}
		fmt.Printf("  %-10s %-19s %-9s %s\n",
			cat.ID, cat.Label, state, covers(len(cat.Apps), len(cat.Domains), len(cat.Settings)))
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

	fmt.Printf("%s - %s\n", cat.Label, covers(len(cat.Apps), len(cat.Domains), len(cat.Settings)))
	if cfg.CategoryApplied(cat) {
		if cat.BlocksAnything() {
			fmt.Printf("blocked now, under the block %q\n", cat.ID)
		} else {
			fmt.Println("on now - this category has no block, it sets browser settings")
		}
	}
	switch missing {
	case 0:
		if cat.BlocksAnything() {
			fmt.Println("all of it is already in the block list; blocking it again would change nothing")
		} else {
			fmt.Println("every setting it asks for is already on; applying it again would change nothing")
		}
	case len(entries):
		fmt.Println("none of it is in force yet")
	default:
		fmt.Printf("%d of these are not in force yet\n", missing)
	}
	fmt.Println()

	fmt.Printf("  %-30s %-16s %s\n", "entry", "state", "covers")
	for _, e := range entries {
		state := "new"
		if e.Present {
			// A setting is on, not blocked. Same column, different verb: this
			// category blocks nothing, and "already blocked" would be the one
			// sentence a reader took away from the list.
			state = "already blocked"
			if e.Kind == policy.EntrySetting {
				state = "already on"
			}
		}
		fmt.Printf("  %-30s %-16s %s\n", e.Label, state, e.Detail)
	}
	if cat.Note != "" {
		fmt.Printf("\nnote: %s\n", cat.Note)
	}
	if missing > 0 {
		if cat.BlocksAnything() {
			fmt.Printf("\nblock all of it with `guard block-category %s`\n", cat.ID)
		} else {
			fmt.Printf("\nturn it on with `guard block-category %s`\n", cat.ID)
		}
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
		if cat.BlocksAnything() {
			fmt.Printf("%s is already blocked in full\n", cat.Label)
		} else {
			fmt.Printf("every setting %s asks for is already on\n", cat.Label)
		}
		reportSkipped(res)
		return
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	activity.Record(activity.Event{
		Kind:   activity.CategoryBlocked,
		Target: cat.Label,
		Detail: covers(len(res.Apps), len(res.Domains), len(res.Settings)),
	})

	switch {
	case res.NewBlock:
		fmt.Printf("blocked %s: %s, around the clock\n",
			cat.Label, covers(len(res.Apps), len(res.Domains), len(res.Settings)))
	case cat.BlocksAnything():
		fmt.Printf("topped up %s: %s\n",
			cat.Label, coversNew(len(res.Apps), len(res.Domains), len(res.Settings)))
	default:
		// No block was created because there was none to create. "Blocked" is
		// the wrong word for a category that only changed browser settings, and
		// it is the word the user would repeat back when something still opens.
		fmt.Printf("turned on %s: %s\n",
			cat.Label, coversNew(len(res.Apps), len(res.Domains), len(res.Settings)))
	}
	reportSkipped(res)

	if cat.Note != "" {
		fmt.Printf("\nnote: %s\n", cat.Note)
	}
	// A settings-only category has no block, so there is nothing to put on a
	// schedule and nothing to lock - and hardening is deliberately not
	// schedulable in the first place (see hardening.go, which says why). Offering
	// either here would be advertising a command that cannot work.
	if cat.BlocksAnything() {
		fmt.Printf("\nput it on a schedule with `guard -label %q -days mon-fri -from 09:00 -to 17:00 add-block %s`\n", cat.Label, cat.ID)
		fmt.Printf("lock it with `guard -until 7d lock %s`\n", cat.ID)
	} else {
		fmt.Printf("\ncheck what is in force with `guard hardening`\n")
	}
}

// covers renders how much a category holds, or how much a top-up changed, and
// drops a half that is zero. Topping up a category that gained sites and no
// applications used to read "0 new applications and 3 new sites", which is a
// count that looks like it failed rather than one that says what happened.
//
// There are three halves now, not two: a category may name applications, sites,
// browser settings, or - as "adult" does - only the last of those.
func covers(apps, sites, settings int) string { return coversWith(apps, sites, settings, "") }

// coversNew is covers for what a top-up changed rather than what the category
// holds, so the numbers read as additions.
func coversNew(apps, sites, settings int) string { return coversWith(apps, sites, settings, "new ") }

// coversWith is the shared rendering. The adjective rides on the noun so that
// plural pluralizes the phrase rather than the bare word: "3 new applications".
// Every half zero cannot happen for a catalog entry - validateCategory refuses a
// category that covers nothing - but it can for a result, where "nothing" is the
// honest word for what changed.
func coversWith(apps, sites, settings int, adj string) string {
	var parts []string
	if apps > 0 {
		parts = append(parts, plural(apps, adj+"application"))
	}
	if sites > 0 {
		parts = append(parts, plural(sites, adj+"site"))
	}
	if settings > 0 {
		parts = append(parts, plural(settings, adj+"browser setting"))
	}
	switch len(parts) {
	case 0:
		return "nothing"
	case 1:
		return parts[0]
	}
	// Three halves are reachable now, and "a and b and c" is not a sentence.
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
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
