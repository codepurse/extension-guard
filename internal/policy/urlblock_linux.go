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

const urlBlocklistKey = "URLBlocklist"

// ApplyDomains reconciles the URL filter for every supported browser. Requires
// root.
func ApplyDomains(cfg Config) error {
	want := cfg.BlockedDomains()

	var errs []string
	for _, k := range ChromiumKinds {
		if err := applyChromiumDomains(k, want); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	if err := applyFirefoxDomains(want); err != nil {
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
func applyChromiumDomains(k Kind, want []string) error {
	dir := chromiumManagedDir[k]
	path := filepath.Join(dir, domainPolicyFileName)
	if len(want) == 0 {
		if _, err := os.Stat(path); err != nil {
			return nil
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	doc := map[string]any{urlBlocklistKey: mapPatterns(want, ChromiumBlockPattern)}
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
func applyFirefoxDomains(want []string) error {
	path := firefoxPoliciesPath()
	if len(want) == 0 {
		if _, err := os.Stat(path); err != nil {
			return nil
		}
	}
	if err := os.MkdirAll(firefoxPoliciesDir, 0o755); err != nil {
		return err
	}
	doc := readFirefoxDoc()
	policies := childMap(doc, "policies")
	if len(want) == 0 {
		delete(policies, "WebsiteFilter")
	} else {
		filter := childMap(policies, "WebsiteFilter")
		filter["Block"] = mapPatterns(want, FirefoxBlockPattern)
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

	out := make([]Status, 0, len(ChromiumKinds)+1)
	for _, k := range ChromiumKinds {
		out = append(out, verifyChromiumDomains(k, want, installed[k]))
	}
	out = append(out, verifyFirefoxDomains(want, installed[Firefox]))
	return out
}

func verifyChromiumDomains(k Kind, want []string, installed bool) Status {
	s := Status{Kind: k, Installed: installed}
	wants := mapPatterns(want, ChromiumBlockPattern)
	if len(wants) == 0 {
		return lockStatus(s, 0, 0)
	}
	present := map[string]bool{}
	if data, err := os.ReadFile(filepath.Join(chromiumManagedDir[k], domainPolicyFileName)); err == nil {
		var doc struct {
			Blocklist []string `json:"URLBlocklist"`
		}
		if json.Unmarshal(data, &doc) == nil {
			for _, v := range doc.Blocklist {
				present[v] = true
			}
		}
	}
	return lockStatus(s, countPresent(wants, present), len(wants))
}

func verifyFirefoxDomains(want []string, installed bool) Status {
	s := Status{Kind: Firefox, Installed: installed}
	wants := mapPatterns(want, FirefoxBlockPattern)
	if len(wants) == 0 {
		return lockStatus(s, 0, 0)
	}
	present := map[string]bool{}
	if data, err := os.ReadFile(firefoxPoliciesPath()); err == nil {
		var doc struct {
			Policies struct {
				WebsiteFilter struct {
					Block []string `json:"Block"`
				} `json:"WebsiteFilter"`
			} `json:"policies"`
		}
		if json.Unmarshal(data, &doc) == nil {
			for _, v := range doc.Policies.WebsiteFilter.Block {
				present[v] = true
			}
		}
	}
	return lockStatus(s, countPresent(wants, present), len(wants))
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
	if err := applyFirefoxDomains(nil); err != nil {
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
