// Package policy manages the browser "force-install" enterprise policies that
// lock the configured extensions in place so they cannot be removed from the
// browser UI. This file holds the platform-independent data model and helpers;
// the actual registry reads/writes live in policy_windows.go (and the managed
// policy files in policy_linux.go).
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Kind identifies a supported browser.
type Kind string

const (
	Chrome  Kind = "chrome"
	Edge    Kind = "edge"
	Brave   Kind = "brave"
	Firefox Kind = "firefox"
)

// ChromiumKinds are the Chromium-based browsers that share the
// ExtensionInstallForcelist policy mechanism.
var ChromiumKinds = []Kind{Chrome, Edge, Brave}

// Target describes what to force-install for one browser. Chromium browsers
// use ExtensionID + UpdateURL; Firefox uses AddonID + InstallURL.
type Target struct {
	ExtensionID string `json:"extensionId,omitempty"`
	UpdateURL   string `json:"updateUrl,omitempty"`
	AddonID     string `json:"addonId,omitempty"`
	InstallURL  string `json:"installUrl,omitempty"`
}

// Extension is one extension to force-install, with a per-browser target (each
// browser force-installs only from its own store, so IDs/URLs differ per
// browser). A browser left empty or as a REPLACE_* placeholder is skipped.
type Extension struct {
	Name    string `json:"name,omitempty"`
	Chrome  Target `json:"chrome"`
	Edge    Target `json:"edge"`
	Brave   Target `json:"brave"`
	Firefox Target `json:"firefox"`
}

// Target returns the extension's target for a browser kind.
func (e Extension) Target(k Kind) Target {
	switch k {
	case Chrome:
		return e.Chrome
	case Edge:
		return e.Edge
	case Brave:
		return e.Brave
	case Firefox:
		return e.Firefox
	}
	return Target{}
}

// Config is the parsed extension-ids.json: the full set of extensions the guard
// force-installs and locks.
type Config struct {
	Extensions []Extension `json:"extensions"`
}

// Targets returns every configured target for a browser kind, one per extension
// (including empty/placeholder targets; callers skip those via
// chromiumForcelistValue / firefoxConfigured).
func (c Config) Targets(k Kind) []Target {
	out := make([]Target, 0, len(c.Extensions))
	for _, e := range c.Extensions {
		out = append(out, e.Target(k))
	}
	return out
}

// Select returns a copy of the config keeping only the extensions whose Name is
// listed in names (case-insensitive). An empty names slice returns the config
// unchanged, so callers that don't filter get every extension. The installer
// uses this to lock only the extensions the user chose to install.
func (c Config) Select(names []string) Config {
	if len(names) == 0 {
		return c
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(strings.ToLower(n)); n != "" {
			want[n] = true
		}
	}
	var out Config
	for _, e := range c.Extensions {
		if want[strings.ToLower(e.Name)] {
			out.Extensions = append(out.Extensions, e)
		}
	}
	return out
}

// UnmarshalJSON accepts both the current multi-extension shape
// ({"extensions": [...]}) and the legacy single-extension flat shape
// ({"chrome": {...}, "firefox": {...}, ...}), wrapping the latter as one
// extension so an already-deployed config keeps loading after the upgrade.
func (c *Config) UnmarshalJSON(data []byte) error {
	var multi struct {
		Extensions []Extension `json:"extensions"`
	}
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	if len(multi.Extensions) > 0 {
		c.Extensions = multi.Extensions
		return nil
	}
	var legacy Extension
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	if legacy != (Extension{}) {
		if legacy.Name == "" {
			legacy.Name = "extension"
		}
		c.Extensions = []Extension{legacy}
	}
	return nil
}

// LoadConfig reads and parses the extension-ids.json file.
func LoadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("parse config: %w", err)
	}
	return c, nil
}

// isPlaceholder reports whether a value is still an unfilled REPLACE_* token.
func isPlaceholder(s string) bool {
	return strings.Contains(s, "REPLACE_")
}

// chromiumForcelistValue builds the "<id>;<update_url>" entry that the
// ExtensionInstallForcelist policy expects. It returns an error when the target
// is incomplete or still contains a placeholder, so callers can skip it.
func chromiumForcelistValue(t Target) (string, error) {
	if t.ExtensionID == "" || t.UpdateURL == "" {
		return "", fmt.Errorf("missing extensionId or updateUrl")
	}
	if isPlaceholder(t.ExtensionID) || isPlaceholder(t.UpdateURL) {
		return "", fmt.Errorf("extensionId/updateUrl is still a placeholder")
	}
	return t.ExtensionID + ";" + t.UpdateURL, nil
}

// chromiumForcelistValues returns the forcelist entries for every configured
// target in the list, skipping incomplete/placeholder ones.
func chromiumForcelistValues(targets []Target) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		if v, err := chromiumForcelistValue(t); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// firefoxConfigured reports whether a Firefox target is ready to apply.
func firefoxConfigured(t Target) bool {
	return t.AddonID != "" && t.InstallURL != "" && !isPlaceholder(t.InstallURL)
}

// configuredFirefox returns the Firefox targets in the list that are ready to
// apply (complete, non-placeholder).
func configuredFirefox(targets []Target) []Target {
	out := make([]Target, 0, len(targets))
	for _, t := range targets {
		if firefoxConfigured(t) {
			out = append(out, t)
		}
	}
	return out
}

// Status reports whether a browser's force-install policy is correctly applied.
// With several extensions configured for a browser, Locked means every one of
// them is force-installed; Detail is "partial (n/total)" when only some are.
type Status struct {
	Kind      Kind   // which browser
	Installed bool   // browser detected on this machine
	Locked    bool   // force-install policy present and correct for all configured extensions
	Detail    string // human-readable note: "ok", "missing", "tampered", "partial (n/m)", "not configured"
}

// lockStatus turns a matched/total tally into a Status detail + locked flag,
// shared by the Windows and Linux verify paths so they report identically.
func lockStatus(s Status, matched, total int) Status {
	switch {
	case total == 0:
		s.Detail = "not configured"
	case matched == total:
		s.Locked, s.Detail = true, "ok"
	case matched == 0:
		s.Detail = "missing"
	default:
		s.Detail = fmt.Sprintf("partial (%d/%d)", matched, total)
	}
	return s
}
