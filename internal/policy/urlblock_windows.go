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
	// firefoxFilterBlockSubkey is Firefox's equivalent. It takes match patterns
	// rather than bare hostnames, hence the separate pattern builder.
	firefoxFilterBlockSubkey = `WebsiteFilter\Block`
)

// ApplyDomains reconciles the URL filter in every supported browser with cfg:
// enabled domains are blocked, domains switched off (by their own flag or by a
// schedule window closing) are unblocked, and any filter entry the guard does not
// manage is preserved. Requires Administrator.
func ApplyDomains(cfg Config) error {
	want := cfg.BlockedDomains()
	stale := cfg.InactiveDomains()

	var errs []string
	for _, k := range ChromiumKinds {
		err := syncNumberedList(
			chromiumPolicyRoot[k]+`\`+urlBlocklistSubkey,
			mapPatterns(want, ChromiumBlockPattern),
			dropExact(mapPatterns(stale, ChromiumBlockPattern)),
		)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	err := syncNumberedList(
		firefoxPolicyRoot+`\`+firefoxFilterBlockSubkey,
		mapPatterns(want, FirefoxBlockPattern),
		dropExact(mapPatterns(stale, FirefoxBlockPattern)),
	)
	if err != nil {
		errs = append(errs, fmt.Sprintf("firefox: %v", err))
	}
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

	out := make([]Status, 0, len(ChromiumKinds)+1)
	for _, k := range ChromiumKinds {
		out = append(out, verifyDomainList(
			Status{Kind: k, Installed: installed[k]},
			chromiumPolicyRoot[k]+`\`+urlBlocklistSubkey,
			mapPatterns(want, ChromiumBlockPattern),
		))
	}
	out = append(out, verifyDomainList(
		Status{Kind: Firefox, Installed: installed[Firefox]},
		firefoxPolicyRoot+`\`+firefoxFilterBlockSubkey,
		mapPatterns(want, FirefoxBlockPattern),
	))
	return out
}

func verifyDomainList(s Status, path string, wants []string) Status {
	if len(wants) == 0 {
		return lockStatus(s, 0, 0)
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
	matched := 0
	for _, w := range wants {
		if present[w] {
			matched++
		}
	}
	return lockStatus(s, matched, len(wants))
}

// RemoveDomains clears every domain the guard manages from every browser's URL
// filter, enabled or not. Used on an authorized teardown; entries the guard did
// not write are left alone.
func RemoveDomains(cfg Config) error {
	managed := cfg.ManagedDomains()
	if len(managed) == 0 {
		return nil
	}
	var errs []string
	for _, k := range ChromiumKinds {
		path := chromiumPolicyRoot[k] + `\` + urlBlocklistSubkey
		if err := syncNumberedList(path, nil, dropExact(mapPatterns(managed, ChromiumBlockPattern))); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	path := firefoxPolicyRoot + `\` + firefoxFilterBlockSubkey
	if err := syncNumberedList(path, nil, dropExact(mapPatterns(managed, FirefoxBlockPattern))); err != nil {
		errs = append(errs, fmt.Sprintf("firefox: %v", err))
	}
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
