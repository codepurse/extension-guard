//go:build windows

package policy

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	// urlBlocklistSubkey is Chromium's URL filter. It lives under the same policy
	// root as the forcelist, so the guard's existing tamper watcher covers it too.
	urlBlocklistSubkey = `URLBlocklist`
	// urlAllowlistSubkey is the override half. Chromium gives an allowlist entry
	// precedence over a blocklist one, which is what lets "*" block everything and
	// three named sites still load. See allowlist.go.
	urlAllowlistSubkey = `URLAllowlist`
	// firefoxFilterBlockSubkey is Firefox's equivalent. It takes match patterns
	// rather than bare hostnames, hence the separate pattern builder.
	firefoxFilterBlockSubkey = `WebsiteFilter\Block`
	// firefoxFilterExceptSubkey is Firefox's override half.
	firefoxFilterExceptSubkey = `WebsiteFilter\Exceptions`
)

// ApplyDomains reconciles the URL filter in every supported browser with cfg:
// enabled domains are blocked, domains switched off (by their own flag or by a
// schedule window closing) are unblocked, and any filter entry the guard does not
// manage is preserved. Requires Administrator.
func ApplyDomains(cfg Config) error {
	want := cfg.BlockedDomains()
	stale := cfg.InactiveDomains()
	// The allowlist mode adds one entry to the block list - the one that blocks
	// everything - and fills the override list. When it is off, both have to be
	// pruned: this is the same reconcile-do-not-accumulate rule the rest of the file
	// follows, and getting it wrong here would leave the whole web blocked after the
	// mode was turned off, which is the worst stale entry in the program.
	allowing := cfg.Allowing().On
	allowed := cfg.Allowing().AllowedSites()
	blockAll, staleAll := []string(nil), []string{ChromiumBlockAll}
	ffBlockAll, ffStaleAll := []string(nil), []string{FirefoxBlockAll}
	wantAllow, staleAllow := []string(nil), allowed
	if allowing {
		blockAll, staleAll = []string{ChromiumBlockAll}, nil
		ffBlockAll, ffStaleAll = []string{FirefoxBlockAll}, nil
		wantAllow, staleAllow = allowed, nil
	}

	var errs []string
	for _, k := range ChromiumKinds {
		err := syncNumberedList(
			chromiumPolicyRoot[k]+`\`+urlBlocklistSubkey,
			append(mapPatterns(want, ChromiumBlockPattern), blockAll...),
			dropExact(append(mapPatterns(stale, ChromiumBlockPattern), staleAll...)),
		)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
		if err := syncNumberedList(
			chromiumPolicyRoot[k]+`\`+urlAllowlistSubkey,
			mapPatterns(wantAllow, ChromiumAllowPattern),
			dropExact(mapPatterns(staleAllow, ChromiumAllowPattern)),
		); err != nil {
			errs = append(errs, fmt.Sprintf("%s allowlist: %v", k, err))
		}
	}
	for _, g := range geckoBrowsers() {
		if err := syncNumberedList(
			g.Root+`\`+firefoxFilterBlockSubkey,
			append(mapPatterns(want, FirefoxBlockPattern), ffBlockAll...),
			dropExact(append(mapPatterns(stale, FirefoxBlockPattern), ffStaleAll...)),
		); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", g.Kind, err))
		}
		if err := syncNumberedList(
			g.Root+`\`+firefoxFilterExceptSubkey,
			mapPatterns(wantAllow, FirefoxAllowPattern),
			dropExact(mapPatterns(staleAllow, FirefoxAllowPattern)),
		); err != nil {
			errs = append(errs, fmt.Sprintf("%s allowlist: %v", g.Kind, err))
		}
	}
	// Best effort, and after the writes: a running Chromium browser will not see
	// any of this until group policy is refreshed. A refresh that fails is retried
	// on the next reconcile cycle and must not turn a block that *was* written into
	// an apply failure, so its error is not joined here.
	_ = refreshBrowserPolicy()
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// VerifyDomains reports, per browser, whether every domain that should be
// blocked right now actually is. Read-only, so it works without elevation.
func VerifyDomains(cfg Config) []Status {
	installed := DetectBrowsers()
	want := cfg.BlockedDomains()
	allowing := cfg.Allowing().On
	allowed := cfg.Allowing().AllowedSites()

	// The allowlist folds into each browser's existing row rather than adding its
	// own. The row means "everything the config asks of this browser's URL filter is
	// in place", and blocking everything is one more thing it asks - splitting it out
	// would let the table read "domains: ok" on a machine where the entry blocking the
	// web had been deleted. Both keys are tallied into one matched/total so a partial
	// count stays meaningful.
	gecko := geckoBrowsers()
	out := make([]Status, 0, len(ChromiumKinds)+len(gecko))
	for _, k := range ChromiumKinds {
		root := chromiumPolicyRoot[k]
		blocked := mapPatterns(want, ChromiumBlockPattern)
		if allowing {
			blocked = append(blocked, ChromiumBlockAll)
		}
		matched, total := tally(root+`\`+urlBlocklistSubkey, blocked)
		if allowing {
			m, t := tally(root+`\`+urlAllowlistSubkey, mapPatterns(allowed, ChromiumAllowPattern))
			matched, total = matched+m, total+t
		}
		out = append(out, lockStatus(Status{Kind: k, Installed: installed[k]}, matched, total))
	}

	ffBlocked := mapPatterns(want, FirefoxBlockPattern)
	if allowing {
		ffBlocked = append(ffBlocked, FirefoxBlockAll)
	}
	for _, g := range gecko {
		matched, total := tally(g.Root+`\`+firefoxFilterBlockSubkey, ffBlocked)
		if allowing {
			m, t := tally(g.Root+`\`+firefoxFilterExceptSubkey, mapPatterns(allowed, FirefoxAllowPattern))
			matched, total = matched+m, total+t
		}
		out = append(out, lockStatus(Status{Kind: g.Kind, Installed: installed[g.Kind]}, matched, total))
	}
	return out
}

// tally counts how many of wants are present in the numbered list at path. A
// missing key counts as nothing present rather than as an error, which is the same
// reading readNumberedList takes: the entries are not there, and that is the fact
// the caller wants.
func tally(path string, wants []string) (matched, total int) {
	if len(wants) == 0 {
		return 0, 0
	}
	present := map[string]bool{}
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE); err == nil {
		if names, err := key.ReadValueNames(-1); err == nil {
			for _, n := range names {
				if v, _, err := key.GetStringValue(n); err == nil {
					present[v] = true
				}
			}
		}
		key.Close()
	}
	for _, w := range wants {
		if present[w] {
			matched++
		}
	}
	return matched, len(wants)
}

// RemoveDomains clears every domain the guard manages from every browser's URL
// filter, enabled or not. Used on an authorized teardown; entries the guard did
// not write are left alone.
func RemoveDomains(cfg Config) error {
	managed := cfg.ManagedDomains()
	if len(managed) == 0 && cfg.Allowlist == nil {
		// Nothing was ever written. The allowlist has to be checked as well as the
		// block list: a config that only ever used the mode has no managed domains at
		// all, and returning early here would leave the web shut.
		return nil
	}
	// Everything the guard may have written, whatever the config currently asks for.
	// The block-all entry above all: a teardown that left it behind would leave the
	// machine with no web at all and no guard to lift it.
	allowed := cfg.Allowing().AllowedSites()

	var errs []string
	for _, k := range ChromiumKinds {
		path := chromiumPolicyRoot[k] + `\` + urlBlocklistSubkey
		drop := append(mapPatterns(managed, ChromiumBlockPattern), ChromiumBlockAll)
		if err := syncNumberedList(path, nil, dropExact(drop)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
		allowPath := chromiumPolicyRoot[k] + `\` + urlAllowlistSubkey
		if err := syncNumberedList(allowPath, nil, dropExact(mapPatterns(allowed, ChromiumAllowPattern))); err != nil {
			errs = append(errs, fmt.Sprintf("%s allowlist: %v", k, err))
		}
	}
	ffDrop := append(mapPatterns(managed, FirefoxBlockPattern), FirefoxBlockAll)
	for _, g := range geckoBrowsers() {
		if err := syncNumberedList(g.Root+`\`+firefoxFilterBlockSubkey, nil, dropExact(ffDrop)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", g.Kind, err))
		}
		ffAllow := g.Root + `\` + firefoxFilterExceptSubkey
		if err := syncNumberedList(ffAllow, nil, dropExact(mapPatterns(allowed, FirefoxAllowPattern))); err != nil {
			errs = append(errs, fmt.Sprintf("%s allowlist: %v", g.Kind, err))
		}
	}
	// Unblocking needs the browser told just as much as blocking did.
	_ = refreshBrowserPolicy()
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// mapPatterns turns normalized hosts into one browser's filter patterns.
func mapPatterns(hosts []string, f func(string) string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, f(h))
	}
	return out
}

// dropExact matches exactly the given filter entries. Unlike the forcelist there
// is no prefix to key on - the value *is* the pattern - so an entry only counts
// as ours when it matches a pattern we would have written.
func dropExact(vals []string) func(string) bool {
	if len(vals) == 0 {
		return nil
	}
	set := make(map[string]bool, len(vals))
	for _, v := range vals {
		set[v] = true
	}
	return func(v string) bool { return set[v] }
}
