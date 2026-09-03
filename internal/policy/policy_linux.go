//go:build linux

package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// chromiumManagedDir maps each Chromium browser to its "managed" policy
// directory. Chromium reads every JSON file dropped there and merges them, so we
// own a single file (policyFileName) and never disturb other policy files.
var chromiumManagedDir = map[Kind]string{
	Chrome: "/etc/opt/chrome/policies/managed",
	Edge:   "/etc/opt/edge/policies/managed",
	Brave:  "/etc/brave/policies/managed",
}

const (
	policyFileName = "extension-guard.json"
	forcelistKey   = "ExtensionInstallForcelist"

	// Firefox reads a single policies.json; we merge our ExtensionSettings entry
	// into it so any pre-existing Firefox policies survive.
	firefoxPoliciesDir  = "/etc/firefox/policies"
	firefoxPoliciesFile = "policies.json"
)

// geckoBrowsers is the Firefox-family half of AllKinds on this platform, and it
// is deliberately shorter than the family: Firefox only, with neither Zen nor
// the discovery that finds forks on Windows.
//
// The reason is where a fork reads its policies from, not what it is called.
// Windows hands every one of them a registry key named after the application, so
// writing one more key covers a browser the guard has only just heard of. Linux
// has no equivalent: Mozilla's engine looks for policies.json in the
// distribution directory *inside the install*, and where that is depends on how
// the browser was installed - a distribution package, a tarball unpacked into a
// home directory, a flatpak whose filesystem the guard cannot write at all.
// There is no single path to write the way /etc/firefox/policies is for Firefox,
// so there is nothing to discover yet.
//
// Naming a browser here before that is solved is the one thing that must not
// happen: every row in the status table and every browser named in a hardening
// gap comes from this list, so it would have the window report a browser as
// covered while nothing was written for it anywhere.
func geckoBrowsers() []GeckoBrowser {
	return []GeckoBrowser{{
		Kind:  Firefox,
		Name:  "Firefox",
		Root:  firefoxPoliciesPath(),
		Image: "firefox",
	}}
}

// resetGeckoBrowsers drops the cached scan on the platform that has one. Nothing
// is discovered or cached here, so it does nothing - it exists so the test helper
// that describes a machine reads the same on every platform.
func resetGeckoBrowsers() {}

// linuxBrowserBins maps each browser to the executables that indicate it is
// installed (looked up on PATH; snap/flatpak browsers expose these names too).
var linuxBrowserBins = map[Kind][]string{
	Chrome:  {"google-chrome", "google-chrome-stable"},
	Edge:    {"microsoft-edge", "microsoft-edge-stable"},
	Brave:   {"brave-browser", "brave"},
	Firefox: {"firefox", "firefox-esr"},
}

// Apply reconciles the force-install policy with cfg across every browser:
// every enabled extension is written, and every disabled one removed. The
// removal half is what lets a schedule release as well as tighten. Writing for a
// browser that isn't installed is harmless. Requires root.
func Apply(cfg Config) error {
	var errs []string
	for _, k := range ChromiumKinds {
		if err := applyChromium(k, cfg.Targets(k)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	if err := applyFirefox(cfg.Targets(Firefox), cfg.InactiveTargets(Firefox)); err != nil {
		errs = append(errs, fmt.Sprintf("firefox: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func applyChromium(k Kind, targets []Target) error {
	vals := chromiumForcelistValues(targets)
	dir := chromiumManagedDir[k]
	if len(vals) == 0 {
		// Nothing active for this browser. We own this file outright, so an existing
		// one must be cleared rather than left holding a stale list - otherwise the
		// last extension to go out of window would stay force-installed. If we never
		// wrote one, there is nothing to do.
		path := filepath.Join(dir, policyFileName)
		if _, err := os.Stat(path); err != nil {
			return nil
		}
		vals = []string{}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	doc := map[string]any{forcelistKey: vals}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, policyFileName), data, 0o644)
}

func applyFirefox(targets, inactive []Target) error {
	configured := configuredFirefox(targets)
	if len(configured) == 0 && len(inactive) == 0 {
		return nil // not configured - skip quietly
	}
	if err := os.MkdirAll(firefoxPoliciesDir, 0o755); err != nil {
		return err
	}
	doc := readFirefoxDoc()
	extSettings := childMap(childMap(doc, "policies"), "ExtensionSettings")
	for _, t := range configured {
		extSettings[t.AddonID] = map[string]any{
			"installation_mode": "force_installed",
			"install_url":       t.InstallURL,
			// The member that makes the lock reach private windows too - see
			// geckoPrivateBrowsingValue in the Windows writer for why it is written
			// unconditionally. A policies.json is read as JSON, so this is a real
			// boolean rather than the registry's 0/1.
			"private_browsing": true,
		}
	}
	// Drop anything switched off. policies.json is shared with policies we did not
	// write, so only our own add-on ids are touched.
	for _, t := range inactive {
		if t.AddonID != "" {
			delete(extSettings, t.AddonID)
		}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(firefoxPoliciesPath(), data, 0o644)
}

// Verify reports the lock status of each browser. A browser is Locked only when
// every extension configured for it is force-installed.
func Verify(cfg Config) []Status {
	installed := DetectBrowsers()
	out := make([]Status, 0, len(ChromiumKinds)+1)
	for _, k := range ChromiumKinds {
		out = append(out, verifyChromium(k, cfg.Targets(k), installed[k]))
	}
	out = append(out, verifyFirefox(cfg.Targets(Firefox), installed[Firefox]))
	return out
}

func verifyChromium(k Kind, targets []Target, installed bool) Status {
	s := Status{Kind: k, Installed: installed}
	wants := chromiumForcelistValues(targets)
	if len(wants) == 0 {
		return lockStatus(s, 0, 0)
	}
	present := map[string]bool{}
	if data, err := os.ReadFile(filepath.Join(chromiumManagedDir[k], policyFileName)); err == nil {
		var doc struct {
			Forcelist []string `json:"ExtensionInstallForcelist"`
		}
		if json.Unmarshal(data, &doc) == nil {
			for _, v := range doc.Forcelist {
				present[v] = true
			}
		}
	}
	matched := 0
	for _, w := range wants {
		if present[w] {
			matched++
		}
	}
	return lockStatus(s, matched, len(wants))
}

func verifyFirefox(targets []Target, installed bool) Status {
	s := Status{Kind: Firefox, Installed: installed}
	configured := configuredFirefox(targets)
	if len(configured) == 0 {
		return lockStatus(s, 0, 0)
	}
	settings := map[string]struct {
		InstallationMode string `json:"installation_mode"`
		InstallURL       string `json:"install_url"`
	}{}
	if data, err := os.ReadFile(firefoxPoliciesPath()); err == nil {
		var doc struct {
			Policies struct {
				ExtensionSettings map[string]struct {
					InstallationMode string `json:"installation_mode"`
					InstallURL       string `json:"install_url"`
				} `json:"ExtensionSettings"`
			} `json:"policies"`
		}
		if json.Unmarshal(data, &doc) == nil {
			settings = doc.Policies.ExtensionSettings
		}
	}
	matched := 0
	for _, t := range configured {
		if e, ok := settings[t.AddonID]; ok && e.InstallationMode == "force_installed" && e.InstallURL == t.InstallURL {
			matched++
		}
	}
	return lockStatus(s, matched, len(configured))
}

// Remove deletes the force-install policy for every configured extension.
func Remove(cfg Config) error {
	var errs []string
	for _, k := range ChromiumKinds {
		if err := removeChromium(k, cfg.Targets(k)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	if err := removeFirefox(cfg.Targets(Firefox)); err != nil {
		errs = append(errs, fmt.Sprintf("firefox: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func removeChromium(k Kind, targets []Target) error {
	// We own the whole policyFileName in the managed dir, so removing it clears
	// every extension we force-installed for this browser at once.
	if err := os.Remove(filepath.Join(chromiumManagedDir[k], policyFileName)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func removeFirefox(targets []Target) error {
	var addonIDs []string
	for _, t := range targets {
		if t.AddonID != "" {
			addonIDs = append(addonIDs, t.AddonID)
		}
	}
	if len(addonIDs) == 0 {
		return nil
	}
	data, err := os.ReadFile(firefoxPoliciesPath())
	if err != nil {
		return nil // nothing to remove
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	policies, _ := doc["policies"].(map[string]any)
	if policies == nil {
		return nil
	}
	ext, _ := policies["ExtensionSettings"].(map[string]any)
	if ext == nil {
		return nil
	}
	for _, id := range addonIDs {
		delete(ext, id)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(firefoxPoliciesPath(), out, 0o644)
}

// DetectBrowsers reports which supported browsers are installed (via PATH).
func DetectBrowsers() map[Kind]bool {
	out := make(map[Kind]bool, len(linuxBrowserBins))
	for _, k := range AllKinds() {
		out[k] = false
		for _, bin := range linuxBrowserBins[k] {
			if _, err := exec.LookPath(bin); err == nil {
				out[k] = true
				break
			}
		}
	}
	return out
}

func firefoxPoliciesPath() string { return filepath.Join(firefoxPoliciesDir, firefoxPoliciesFile) }

// readFirefoxDoc loads the existing policies.json as a generic document, or
// returns an empty one so Apply can merge into it without clobbering other keys.
func readFirefoxDoc() map[string]any {
	data, err := os.ReadFile(firefoxPoliciesPath())
	if err != nil {
		return map[string]any{}
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil || doc == nil {
		return map[string]any{}
	}
	return doc
}

// childMap returns parent[key] as a map, creating it if absent or the wrong type.
func childMap(parent map[string]any, key string) map[string]any {
	if m, ok := parent[key].(map[string]any); ok {
		return m
	}
	m := map[string]any{}
	parent[key] = m
	return m
}
