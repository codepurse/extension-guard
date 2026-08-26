package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/codepurse/extension-guard/internal/activity"
	"github.com/codepurse/extension-guard/internal/enforce"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
	"github.com/codepurse/extension-guard/internal/usage"
)

// This file holds the commands for scheduled blocks: listing them, locking one
// against early release, and adopting a hand-edited config file.
//
// The last one exists because the config file is no longer authoritative (see
// internal/policy/trust.go). Editing extension-ids.json in a text editor is
// still the natural way to describe a schedule, but the service would revert it
// as tamper - so "commit" is the authorized way to say "yes, I meant that".

// blocksCmd lists each block, whether it is enforcing right now, and its lock.
// Read-only and admin-free, so it can be run to check a schedule at any time.
func blocksCmd(cfg policy.Config) {
	now := time.Now()
	blocksAt(cfg, now, cfg.SpentAt(now))
}

// blocksAt is the listing itself, for a given moment and a given set of spent
// budgets. Both are parameters rather than read here, because what a block's row
// says depends on the hour and on how much of a limit is left, and a test that had
// to arrange the real clock and the real ledger to check the wording would end up
// checking neither.
func blocksAt(cfg policy.Config, now time.Time, spent policy.Spent) {
	if len(cfg.Blocks) == 0 {
		fmt.Println("no blocks configured; every enabled extension is enforced around the clock")
		return
	}
	fmt.Printf("  %-12s %-9s %-22s %-18s %-18s %s\n", "id", "state", "schedule", "governs", "limit", "lock")
	for _, b := range cfg.Blocks {
		// Three states rather than two, because a block with a daily limit and budget
		// left is neither enforcing nor out of window, and calling that "idle" would
		// read as a fault in the one case where the user most wants to know it isn't.
		state := "idle"
		switch {
		case b.EnforcingAt(now, spent):
			state = "enforcing"
		case b.HasLimit() && b.InWindow(now):
			state = "in budget"
		}
		lock := "-"
		if locked, until := b.LockedAt(now); locked {
			if until.IsZero() {
				lock = "locked (unreadable deadline)"
			} else {
				lock = "locked until " + until.Local().Format("Mon 2 Jan 15:04")
			}
		}
		fmt.Printf("  %-12s %-9s %-22s %-18s %-18s %s\n",
			b.ID, state, b.ScheduleSummary(), b.GovernedSummary(), limitColumn(b, spent), lock)
	}
	if spent.Unreadable {
		fmt.Printf("\nwarning: the usage record at %s could not be read\n", usage.Path())
		fmt.Println("(every daily limit counts as used up until the guard rewrites it, which it does from its own")
		fmt.Println(" running count within half a minute, or from zero if it has to be restarted)")
	}
	if invalid := cfg.Validate(); invalid != nil {
		fmt.Printf("\nwarning: %v\n", invalid)
		fmt.Println("(the schedule is being ignored; every enabled extension stays enforced until this is fixed)")
	}
}

// limitColumn renders a block's budget and what is left of it, or "-" for a block
// without one. Both halves are shown because either alone is the wrong number to
// read: the budget without the spend does not say whether the app opens right now,
// and the spend without the budget does not say how close it is.
func limitColumn(b policy.Block, spent policy.Spent) string {
	limit, ok := b.LimitFor()
	if !ok {
		return "-"
	}
	if spent.Unreadable {
		return policy.HumanDuration(limit) + "/day, unknown"
	}
	return fmt.Sprintf("%s of %s left", policy.HumanDuration(b.Remaining(spent)), policy.HumanDuration(limit))
}

// blockSpec is what the add-block flags describe: one block, with at most one
// window. A block with several windows is still a config-file job (edit and
// `guard commit`); one window covers "work hours" and "evenings", which is what
// people actually set up.
type blockSpec struct {
	label      string
	days       string // "mon,tue" / "weekdays" / "" for every day
	from, to   string // "HH:MM"; both empty means an always-on block
	limit      string // daily budget: "45m", "1h30m", or a number of minutes
	extensions string // comma-separated names; empty with the others means "everything"
	domains    string
	apps       string
}

// addBlockCmd creates a scheduled block.
//
// The gate here is the opposite of every other "add" in the guard, and it is
// worth being explicit about why. Blocking a site or an app adds protection, so
// it costs admin and nothing more. A *schedule* takes something that was enforced
// around the clock and enforces it only sometimes - so creating a block with
// windows weakens protection and takes the password, exactly like unblocking a
// site. A block with no windows is always on: it cannot weaken anything, so it is
// free. See policy.Block.Narrows.
//
// A daily limit is the same inversion, only more obviously so: an application that
// was blocked outright becomes one you may use for forty-five minutes, which is
// exactly the kind of change the password exists to gate.
func addBlockCmd(cfg policy.Config, cfgPath, id string, spec blockSpec, password string) {
	block, err := buildBlock(cfg, id, spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.AddBlock(block); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	// Everything that can refuse the block is checked before the password is asked
	// for, the same way commit does it: being prompted for a password and *then*
	// told the schedule was unusable wastes the one step that costs the user
	// something.
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, "(nothing was changed)")
		os.Exit(1)
	}
	if block.Narrows() && !scm.IsPaused() {
		requirePassword(password, "putting protection on a schedule")
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	activity.Record(activity.Event{
		Kind:   activity.BlockCreated,
		Target: blockName(block),
		Detail: blockDetail(block),
	})

	fmt.Printf("created block %q: %s, governing %s\n", block.ID, block.ScheduleSummary(), block.GovernedSummary())
	if limit := block.LimitSummary(); limit != "" {
		fmt.Printf("(%s allowed, and blocked once that is used up - `guard limits` shows what is left)\n", limit)
	} else if block.Narrows() {
		fmt.Println("(what it governs is now enforced only during those windows)")
	}
	fmt.Printf("lock it with `guard -until 7d lock %s`\n", block.ID)
}

// blockDetail describes a block for the activity log. The limit is named where
// there is one, because "created a block governing Steam" and "created a block
// allowing 45m of Steam a day" are very different facts to find in a record.
func blockDetail(b policy.Block) string {
	detail := b.ScheduleSummary() + ", governing " + b.GovernedSummary()
	if limit := b.LimitSummary(); limit != "" {
		detail += ", limited to " + limit
	}
	return detail
}

// buildBlock turns the flags into a block, resolving what it governs against the
// config so a typo is refused here rather than silently governing nothing.
func buildBlock(cfg policy.Config, id string, spec blockSpec) (policy.Block, error) {
	b := policy.Block{
		Label:      strings.TrimSpace(spec.label),
		Limit:      strings.TrimSpace(spec.limit),
		Extensions: splitAndTrim(spec.extensions),
		Domains:    splitAndTrim(spec.domains),
		Apps:       splitAndTrim(spec.apps),
	}
	if b.HasLimit() {
		// Normalized here rather than left as typed, so that "45" becomes "45m" in the
		// config and the stored block says what it means. It also fails now, with the
		// flag in front of the user, instead of inside Validate a few lines later.
		limit, err := policy.ParseLimit(b.Limit)
		if err != nil {
			return policy.Block{}, err
		}
		b.Limit = policy.HumanDuration(limit)
	}
	b.ID = strings.TrimSpace(id)
	if b.ID == "" {
		// The status window asks for a name, not an id; derive one so it does not
		// have to invent identifiers on the user's behalf.
		name := b.Label
		if name == "" {
			name = "block"
		}
		b.ID = policy.NewBlockID(name, func(candidate string) bool {
			_, taken := cfg.Block(candidate)
			return taken
		})
	}

	from, to := strings.TrimSpace(spec.from), strings.TrimSpace(spec.to)
	switch {
	case from == "" && to == "":
		// Always on. This is the shape a lock alone needs: "everything, until Friday".
	case from == "" || to == "":
		return policy.Block{}, fmt.Errorf("-from and -to go together (a window needs both ends)")
	default:
		days, err := parseDayList(spec.days)
		if err != nil {
			return policy.Block{}, err
		}
		b.Windows = []policy.Window{{Days: days, Start: from, End: to}}
	}
	return b, nil
}

// dayPresets are the groupings people say out loud, so neither the CLI nor the
// status window has to spell out five day names for the common case.
var dayPresets = map[string][]string{
	"daily":    nil, // no days listed means every day
	"everyday": nil,
	"all":      nil,
	"weekdays": {"mon", "tue", "wed", "thu", "fri"},
	"weekends": {"sat", "sun"},
}

// parseDayList accepts "mon,wed,fri", a preset like "weekdays", or empty for
// every day. Day names themselves are validated by policy.Validate, which is the
// one place that knows the accepted spellings.
func parseDayList(s string) ([]string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	if trimmed == "" {
		return nil, nil
	}
	if days, ok := dayPresets[trimmed]; ok {
		return days, nil
	}
	days := splitAndTrim(strings.ReplaceAll(trimmed, " ", ","))
	if len(days) == 0 {
		return nil, fmt.Errorf("no days in %q", s)
	}
	return days, nil
}

// removeBlockCmd deletes a block, returning whatever it governed to being
// enforced around the clock.
//
// That reads like strengthening, and usually is - but not always: when two blocks
// govern the same thing, its enforced time is the union of their windows, and
// dropping one can narrow that union. Deciding which case applies is the
// window-coverage reasoning schedule.go deliberately refuses to do, so this takes
// the password either way. A locked block is refused outright, password or not.
func removeBlockCmd(cfg policy.Config, cfgPath, id, password string) {
	if strings.TrimSpace(id) == "" {
		fmt.Fprintln(os.Stderr, "error: block id required, e.g. `guard remove-block work`")
		os.Exit(2)
	}
	block, ok := cfg.Block(id)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: no block with id %q\n", id)
		fmt.Fprintln(os.Stderr, "(run `guard blocks` to see them)")
		os.Exit(1)
	}
	proposed := cfg
	proposed.Blocks = append([]policy.Block(nil), cfg.Blocks...)
	proposed.RemoveBlock(block.ID)
	if err := policy.CheckLockedBlocks(cfg, proposed, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, "(nothing was changed)")
		os.Exit(1)
	}
	if !scm.IsPaused() {
		requirePassword(password, "removing a scheduled block")
	}
	writeConfig(proposed, cfgPath)
	must(enforce.Default().Apply(activeNow(proposed)))
	activity.Record(activity.Event{
		Kind:   activity.BlockRemoved,
		Target: blockName(block),
		Detail: block.GovernedSummary() + " is enforced around the clock again",
	})
	fmt.Printf("removed block %q; %s is enforced around the clock again\n", block.ID, block.GovernedSummary())
}

// lockCmd locks a block so it cannot be weakened before the given time.
//
// Locking needs admin but not the uninstall password: like enabling an extension
// or applying an update, it only strengthens protection. Shortening a lock is
// what needs authority, and no command can do that - a lock runs out on its own.
func lockCmd(cfg policy.Config, cfgPath, id, until string) {
	if strings.TrimSpace(id) == "" {
		fmt.Fprintln(os.Stderr, "error: block id required, e.g. `guard -until 72h lock work`")
		os.Exit(2)
	}
	if strings.TrimSpace(until) == "" {
		fmt.Fprintln(os.Stderr, "error: -until required, e.g. -until 72h, -until 2026-09-01, -until 2026-09-01T17:00")
		os.Exit(2)
	}
	deadline, err := parseUntil(until, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	block, ok := cfg.Block(id)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: no block with id %q\n", id)
		os.Exit(1)
	}
	if locked, current := block.LockedAt(time.Now()); locked && !deadline.After(current) {
		fmt.Fprintf(os.Stderr, "error: %q is already locked until %s; a lock can be extended but not shortened\n",
			block.ID, current.Local().Format(time.RFC1123))
		os.Exit(1)
	}

	for i := range cfg.Blocks {
		if strings.EqualFold(cfg.Blocks[i].ID, block.ID) {
			cfg.Blocks[i].LockedUntil = deadline.Format(time.RFC3339)
		}
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	activity.Record(activity.Event{
		Kind:   activity.BlockLocked,
		Target: blockName(block),
		Detail: "until " + deadline.Local().Format(time.RFC1123),
	})
	fmt.Printf("%s is locked until %s\n", block.ID, deadline.Local().Format(time.RFC1123))
	fmt.Println("it cannot be weakened or removed before then, with or without the password")
}

// commitCmd adopts a hand-edited config file as the enforced one.
//
// It reads the file directly and runs before the trusted copy is reconciled,
// because reconciling first would revert the very edit being submitted. It
// requires the uninstall password: unlike the toggles, a commit can redefine
// enforcement wholesale, so it gets the same gate as turning protection off.
// Locked blocks are checked first and refuse the commit outright - the password
// is not supposed to be able to break a commitment.
func commitCmd(cfgPath, password string) {
	proposed, err := policy.LoadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := proposed.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, "(nothing was changed)")
		os.Exit(1)
	}
	if current, ok := policy.TrustedConfig(); ok {
		if err := policy.CheckLockedBlocks(current, proposed, time.Now()); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			fmt.Fprintln(os.Stderr, "(nothing was changed)")
			os.Exit(1)
		}
	}
	requirePassword(password, "committing an edited config")
	writeConfig(proposed, cfgPath)

	fmt.Println("config committed")
	blocksCmd(proposed)
}

// parseUntil accepts the shapes a person would reasonably type for a deadline:
// a duration from now ("72h", "7d"), a plain local date ("2026-09-01"), a local
// date and time ("2026-09-01T17:00"), or a full RFC 3339 timestamp with a zone.
func parseUntil(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty deadline")
	}

	// "7d" - Go durations stop at hours, and days are the natural unit here.
	if days, ok := strings.CutSuffix(strings.ToLower(s), "d"); ok {
		if n, err := strconv.Atoi(days); err == nil {
			if n <= 0 {
				return time.Time{}, fmt.Errorf("deadline %q is not in the future", s)
			}
			return now.Add(time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return time.Time{}, fmt.Errorf("deadline %q is not in the future", s)
		}
		return now.Add(d), nil
	}

	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			if !t.After(now) {
				return time.Time{}, fmt.Errorf("deadline %q is not in the future", s)
			}
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot read deadline %q (try 72h, 7d, 2026-09-01, or 2026-09-01T17:00)", s)
}

// blockName is what a block is called in the activity log: the name the user gave
// it, falling back to the derived id. The log is read by a person, and "Evenings"
// says more than "evenings-2".
func blockName(b policy.Block) string {
	if name := strings.TrimSpace(b.Label); name != "" {
		return name
	}
	return b.ID
}
