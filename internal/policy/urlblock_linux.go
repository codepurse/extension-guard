//go:build linux

package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// domainPolicyFileName is deliberately a *different* file from policyFileName.
// Chromium merges every JSON file in the managed directory, and the extension
// enforcer rewrites its own file wholesale - so sharing one file would mean
// whichever enforcer ran second erased the other's policy. Separate files let the
// two reconcile independently.
const domainPolicyFileName = "extension-guard-domains.json"

const (
	urlBlocklistKey = "URLBlocklist"
	// urlAllowlistKey is the override half of the allowlist mode. See allowlist.go.
	urlAllowlistKey = "URLAllowlist"
)

// ApplyDomains reconciles the URL filter for every supported browser. Requires
// root.
func ApplyDomains(cfg Config) error {
	want := cfg.BlockedDomains()
	allowing := cfg.Allowing().On
	allowed := cfg.Allowing().AllowedSites()

	var errs []string
	for _, k := range ChromiumKinds {
		if err := applyChromiumDomains(k, want, allowing, allowed); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	if err := applyFirefoxDomains(want, allowing, allowed); err != nil {
		errs = append(errs, fmt.Sprintf("firefox: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// applyChromiumDomains owns its policy file outright, so it writes the wanted
// list wholesale - which reconciles by construction. An empty list clears a file
// we previously wrote rather than leaving stale blocks behind, but does not
// create one where none existed.
func applyChromiumDomains(k Kind, want []string, allowing bool, allowed []string) error {
	dir := chromiumManagedDir[k]
	path := filepath.Join(dir, domainPolicyFileName)
	if len(want) == 0 && !allowing {
		if _, err := os.Stat(path); err != nil {
			return nil
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	blocked := mapPatterns(want, ChromiumBlockPattern)
	doc := map[string]any{}
	if allowing {
		// The file is written wholesale, so the mode being off simply leaves both keys
		// out - there is no stale entry to prune, which is the one thing this platform
		// gets for free over the registry.
		blocked = append(blocked, ChromiumBlockAll)
		doc[urlAllowlistKey] = mapPatterns(allowed, ChromiumAllowPattern)
	}
	doc[urlBlocklistKey] = blocked
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// applyFirefoxDomains merges into the shared policies.json, replacing only the
// WebsiteFilter block list. Reading the whole document first is what keeps the
// extension enforcer's ExtensionSettings - and any policy the machine's owner set
// up - intact when both run in the same cycle.
func applyFirefoxDomains(want []string, allowing bool, allowed []string) error {
	path := firefoxPoliciesPath()
	if len(want) == 0 && !allowing {
		if _, err := os.Stat(path); err != nil {
			return nil
		}
	}
	if err := os.MkdirAll(firefoxPoliciesDir, 0o755); err != nil {
		return err
	}
	doc := readFirefoxDoc()
	policies := childMap(doc, "policies")
	if len(want) == 0 && !allowing {
		delete(policies, "WebsiteFilter")
	} else {
		blocked := mapPatterns(want, FirefoxBlockPattern)
		filter := childMap(policies, "WebsiteFilter")
		if allowing {
			blocked = append(blocked, FirefoxBlockAll)
			filter["Exceptions"] = mapPatterns(allowed, FirefoxAllowPattern)
		} else {
			// Reconciled, not accumulated: the mode going off has to take its exceptions
			// with it, or a site allowed under it stays reachable afterwards.
			delete(filter, "Exceptions")
		}
		filter["Block"] = blocked
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// VerifyDomains reports, per browser, whether every domain that should be blocked
// right now actually is.
func VerifyDomains(cfg Config) []Status {
	installed := DetectBrowsers()
	want := cfg.BlockedDomains()

	allowing := cfg.Allowing().On
	allowed := cfg.Allowing().AllowedSites()

	out := make([]Status, 0, len(ChromiumKinds)+1)
	for _, k := range ChromiumKinds {
		out = append(out, verifyChromiumDomains(k, want, allowing, allowed, installed[k]))
	}
	out = append(out, verifyFirefoxDomains(want, allowing, allowed, installed[Firefox]))
	return out
}

func verifyChromiumDomains(k Kind, want []string, allowing bool, allowed []string, installed bool) Status {
	s := Status{Kind: k, Installed: installed}
	wants := mapPatterns(want, ChromiumBlockPattern)
	var allowWants []string
	if allowing {
		wants = append(wants, ChromiumBlockAll)
		allowWants = mapPatterns(allowed, ChromiumAllowPattern)
	}
	if len(wants) == 0 && len(allowWants) == 0 {
		return lockStatus(s, 0, 0)
	}
	present := map[string]bool{}
	allowPresent := map[string]bool{}
	if data, err := os.ReadFile(filepath.Join(chromiumManagedDir[k], domainPolicyFileName)); err == nil {
		var doc struct {
			Blocklist []string `json:"URLBlocklist"`
			Allowlist []string `json:"URLAllowlist"`
		}
		if json.Unmarshal(data, &doc) == nil {
			for _, v := range doc.Blocklist {
				present[v] = true
			}
			for _, v := range doc.Allowlist {
				allowPresent[v] = true
			}
		}
	}
	// One tally over both keys, for the reason the Windows half states: half of this
	// mode applied is not the mode, and it must not read as "ok".
	matched := countPresent(wants, present) + countPresent(allowWants, allowPresent)
	return lockStatus(s, matched, len(wants)+len(allowWants))
}

func verifyFirefoxDomains(want []string, allowing bool, allowed []string, installed bool) Status {
	s := Status{Kind: Firefox, Installed: installed}
	wants := mapPatterns(want, FirefoxBlockPattern)
	var allowWants []string
	if allowing {
		wants = append(wants, FirefoxBlockAll)
		allowWants = mapPatterns(allowed, FirefoxAllowPattern)
	}
	if len(wants) == 0 && len(allowWants) == 0 {
		return lockStatus(s, 0, 0)
	}
	present := map[string]bool{}
	allowPresent := map[string]bool{}
	if data, err := os.ReadFile(firefoxPoliciesPath()); err == nil {
		var doc struct {
			Policies struct {
				WebsiteFilter struct {
					Block      []string `json:"Block"`
					Exceptions []string `json:"Exceptions"`
				} `json:"WebsiteFilter"`
			} `json:"policies"`
		}
		if json.Unmarshal(data, &doc) == nil {
			for _, v := range doc.Policies.WebsiteFilter.Block {
				present[v] = true
			}
			for _, v := range doc.Policies.WebsiteFilter.Exceptions {
				allowPresent[v] = true
			}
		}
	}
	matched := countPresent(wants, present) + countPresent(allowWants, allowPresent)
	return lockStatus(s, matched, len(wants)+len(allowWants))
}

// RemoveDomains clears the guard's URL filter entries on an authorized teardown.
func RemoveDomains(cfg Config) error {
	var errs []string
	for _, k := range ChromiumKinds {
		path := filepath.Join(chromiumManagedDir[k], domainPolicyFileName)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	if err := applyFirefoxDomains(nil, false, nil); err != nil {
		errs = append(errs, fmt.Sprintf("firefox: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func mapPatterns(hosts []string, f func(string) string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, f(h))
	}
	return out
}

func countPresent(wants []string, present map[string]bool) int {
	n := 0
	for _, w := range wants {
		if present[w] {
			n++
		}
	}
	return n
}
