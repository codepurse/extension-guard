//go:build windows

package policy

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/codepurse/extension-guard/internal/scm"
)

// This file closes the hole that left a screen recorder force-installed in
// somebody's browser months after it had gone from their config.
//
// The Windows forcelist is a key the guard shares. An administrator may have set
// policies of their own there, so syncNumberedList keeps every entry it does not
// recognize, and dropForcelist recognizes an entry by asking whether the current
// config names it. Both halves are right on their own and wrong together: an id
// that leaves the config stops being recognized, so from the next reconcile
// onward the guard reads its own past work as a stranger's policy and protects it
// for ever. Nothing in the app can then reach it - not a toggle, not a pause, not
// an uninstall - because none of them know it is there.
//
// The fix is for the guard to write down what it wrote. "Did I put this here?"
// is a question about history, and a config only ever describes the present.
//
// The record lives in the state store beside the trusted config rather than in
// the config itself. What the guard has written to the registry is a fact about
// this machine, not a preference somebody set, and putting it in the config would
// also change the bytes every config encodes to - which is what the trusted copy
// is compared against, byte for byte, to detect tampering. See trust.go.
//
// Linux needs none of this: there applyChromium rewrites a managed policy file
// the guard owns outright, so a dropped id disappears with the rewrite and no
// stale entry can survive. This is a Windows problem because only on Windows is
// the list shared.

// writtenRecord is what gets stored: the extension ids the guard has written, per
// browser. Ids only, no update URL - dropForcelist matches on the id prefix
// precisely so a store moving its endpoint does not orphan an entry, and the
// record has no business being fussier than the matcher.
type writtenRecord map[string][]string

// Indirection so the tests can exercise this without a registry. Same pattern,
// and the same reason, as gprefresh_windows.go.
var (
	setWrittenTargets = scm.SetWrittenTargets
	getWrittenTargets = scm.GetWrittenTargets
)

// managedIDs are the ids cfg names for a browser, enabled or not. Both halves
// count as the guard's: a disabled extension is one it is actively keeping out of
// the forcelist, which it can only do while it still recognizes the id.
func managedIDs(cfg Config, k Kind) []string {
	seen := make(map[string]bool)
	for _, e := range cfg.Extensions {
		t := e.Target(k)
		id := t.ExtensionID
		if k == Firefox || k == Zen {
			id = t.AddonID
		}
		id = strings.TrimSpace(id)
		if id == "" || isPlaceholder(id) {
			continue
		}
		seen[id] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	// Sorted so the stored value is stable: an unsorted map walk would rewrite the
	// registry on every reconcile with the same set in a different order.
	sort.Strings(out)
	return out
}

// loadWrittenTargets reads the record. An absent or unreadable one reads as
// empty, which is the safe direction: the guard then prunes only what the config
// names, exactly as it did before this file existed.
func loadWrittenTargets() writtenRecord {
	s, ok := getWrittenTargets()
	if !ok || strings.TrimSpace(s) == "" {
		return writtenRecord{}
	}
	var rec writtenRecord
	if err := json.Unmarshal([]byte(s), &rec); err != nil {
		return writtenRecord{}
	}
	return rec
}

// forgottenIDs are ids the guard wrote for a browser and cfg no longer names at
// all - the orphans. They are what the drop predicates need on top of the
// inactive targets they already handle.
//
// An id the config still names is never forgotten, whether it is switched on or
// off: the ordinary active/inactive reconcile owns that one, and returning it
// here would ask for it to be dropped in the same pass that wants it written.
func forgottenIDs(cfg Config, k Kind) []string {
	rec := loadWrittenTargets()
	prev := rec[string(k)]
	if len(prev) == 0 {
		return nil
	}
	managed := make(map[string]bool)
	for _, id := range managedIDs(cfg, k) {
		managed[id] = true
	}
	var out []string
	for _, id := range prev {
		if !managed[id] {
			out = append(out, id)
		}
	}
	return out
}

// recordWrittenTargets replaces the record with what cfg names now. It runs
// after a reconcile, so an id that was just pruned is gone from the record too
// and the next pass has no reason to look at it again.
//
// Best effort by design: failing to record is worth a quieter complaint than
// failing to enforce, and the record is only ever consulted to prune *more* than
// the config asks for. A missing one costs the cleanup, not the protection.
func recordWrittenTargets(cfg Config) {
	rec := writtenRecord{}
	for _, k := range append(append([]Kind{}, ChromiumKinds...), Firefox) {
		if ids := managedIDs(cfg, k); len(ids) > 0 {
			rec[string(k)] = ids
		}
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = setWrittenTargets(string(data))
}
