package policy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

// This file closes the gap that made the Edge bug permanent for everybody who
// had already installed.
//
// A per-browser store id is not a preference. It is a fact about where an
// extension is published, the user has no way to know it, and getting it wrong
// means that browser filters nothing while the status window still reports
// protection. So when a shipped id is corrected, the correction has to reach
// machines that already exist - and until this file, none of the three paths
// carried it:
//
//   - The installer lays down extension-ids.default.json, but with
//     onlyifdoesntexist: an upgrade keeps the config it finds, which is right
//     (it must not replace a household's blocks) and leaves the stale id in
//     place.
//   - The installer runs `select` on first install only, deliberately, so an
//     upgrade cannot re-enable an extension somebody turned off. Nothing else
//     reads the template.
//   - The in-app updater never sees the template at all: manifest.json lists
//     the two binaries and nothing else, so a machine that updates in place
//     gets new code beside an old template.
//
// Hence the catalog is compiled into the binary rather than read from disk. The
// ids then travel by whichever route the new guard.exe arrived, there is no
// second file to keep in sync with the code that reads it, and an update cannot
// half-arrive. The on-disk template stays exactly as it was: it is the starter
// config for a fresh install, which needs blocks and toggles the catalog has no
// business carrying.

//go:embed storecatalog.json
var catalogJSON []byte

// StoreCatalog is the shipped store identity of every extension this build knows how
// to force-install: which id, from which store, per browser.
//
// It carries no Disabled flags, no blocks, no domains and no apps, and that
// omission is the point. Those are the machine's, and an upgrade that adopted
// them would be overwriting the user's own decisions with the developer's.
type StoreCatalog struct {
	Extensions []Extension `json:"extensions"`
}

// EmbeddedCatalog returns the catalog compiled into this binary.
func EmbeddedCatalog() (StoreCatalog, error) {
	var cat StoreCatalog
	if err := json.Unmarshal(catalogJSON, &cat); err != nil {
		return StoreCatalog{}, fmt.Errorf("parse embedded catalog: %w", err)
	}
	return cat, nil
}

// catalogKinds are the browsers a catalog entry can speak for, which is one per
// Target field rather than one per Kind: Zen is absent because it shares
// Firefox's target, and adopting it separately would write the same value twice
// and make the change list say so. See Extension.Target.
var catalogKinds = []Kind{Chrome, Edge, Brave, Firefox}

// catalogSays reports whether a catalog target actually names a place to install
// from, using the same completeness rules the enforcement paths apply - so a
// target this accepts is one that would really be written, and a target it
// rejects is one that would have been skipped anyway.
//
// An incomplete or still-REPLACE_* entry means the catalog has no opinion about
// that browser, which is not the same as an instruction to blank the machine's
// value. Sieve ships with no Edge id because Sieve has no Edge listing yet; a
// machine that had somehow acquired one must keep it.
func catalogSays(k Kind, t Target) bool {
	if k == Firefox || k == Zen {
		return firefoxConfigured(t)
	}
	_, err := chromiumForcelistValue(t)
	return err == nil
}

// AdoptCatalog brings cfg's store ids up to date from cat and reports what
// changed, one line per change, empty when the config already agreed.
//
// What it will do is narrow on purpose. It rewrites per-browser targets, and it
// appends extensions the catalog has and the config does not. Everything else
// the config says is the machine's own and is carried through untouched: the
// blocks, the domains, the apps, the allowlist, the hardening, the reset hour,
// the update mode - and, above all, every Disabled flag. Somebody who turned an
// extension off chose that, and an id correction is not a licence to revisit it.
//
// A new extension arrives disabled for the same reason. Widening the catalog is
// how a later version offers something; force-installing it into a browser
// nobody asked would change what is blocked on a machine without anybody
// agreeing to it, and the first sign would be a site that stopped working for
// reasons the status window did not explain. Listed-but-off puts the choice
// where it belongs, in the window, next to the extensions already there.
//
// This only ever adds enforcement or corrects where enforcement points, which is
// why the callers do not ask for the password. It is the same reasoning `lock`
// and `enable-extension` already run on: authority is needed to weaken
// protection, and nothing here can.
func (c Config) AdoptCatalog(cat StoreCatalog) (Config, []string) {
	var changes []string

	byName := make(map[string]Extension, len(cat.Extensions))
	order := make([]string, 0, len(cat.Extensions))
	for _, e := range cat.Extensions {
		n := strings.ToLower(strings.TrimSpace(e.Name))
		if n == "" {
			continue
		}
		if _, dup := byName[n]; !dup {
			order = append(order, n)
		}
		byName[n] = e
	}

	// Copy before mutating: Config is a value but its slice header is shared, so
	// writing through the range variable's index would edit the caller's config
	// even on the paths that decide to change nothing.
	out := c
	out.Extensions = append([]Extension(nil), c.Extensions...)

	have := make(map[string]bool, len(out.Extensions))
	for i := range out.Extensions {
		name := strings.ToLower(strings.TrimSpace(out.Extensions[i].Name))
		have[name] = true
		want, ok := byName[name]
		if !ok {
			// An extension the catalog has never heard of. Left exactly as it is: this
			// is somebody's own addition, and the catalog not naming it says nothing
			// about whether it should be enforced.
			continue
		}
		for _, k := range catalogKinds {
			wt := want.Target(k)
			if !catalogSays(k, wt) {
				continue
			}
			if out.Extensions[i].Target(k) == wt {
				continue
			}
			was := out.Extensions[i].Target(k)
			out.Extensions[i].setTarget(k, wt)
			changes = append(changes, fmt.Sprintf("%s: %s id %s", displayName(out.Extensions[i]), k, describeTargetChange(k, was, wt)))
		}
		// The label is cosmetic, so it follows the catalog only when the config has
		// nothing to show - never overwriting a name somebody chose to type.
		if strings.TrimSpace(out.Extensions[i].Label) == "" && strings.TrimSpace(want.Label) != "" {
			out.Extensions[i].Label = want.Label
		}
	}

	for _, n := range order {
		if have[n] {
			continue
		}
		add := byName[n]
		add.Disabled = true
		out.Extensions = append(out.Extensions, add)
		changes = append(changes, fmt.Sprintf("%s: added to the catalog, switched off until you turn it on", displayName(add)))
	}

	return out, changes
}

// describeTargetChange says what actually moved, because "changed" is not enough
// to read a record with. A browser going from nothing to an id is the Edge case
// this file exists for and reads as protection arriving; an id being replaced is
// a re-publish and reads differently.
func describeTargetChange(k Kind, was, now Target) string {
	old := was.ExtensionID
	next := now.ExtensionID
	if k == Firefox || k == Zen {
		old, next = was.AddonID, now.AddonID
	}
	switch {
	case strings.TrimSpace(old) == "":
		return "set to " + next + " (this browser had none)"
	case isPlaceholder(old):
		return "set to " + next + " (was still a placeholder)"
	case old == next:
		// Same id, different update URL - a store endpoint move.
		return "kept, update URL corrected"
	default:
		return "corrected from " + old + " to " + next
	}
}

// displayName is the extension's friendly label, falling back to the identifier
// the CLI uses, so a change line names something the reader can act on.
func displayName(e Extension) string {
	if l := strings.TrimSpace(e.Label); l != "" {
		return l
	}
	return strings.TrimSpace(e.Name)
}
