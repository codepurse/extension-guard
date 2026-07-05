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
//
// Disabled keeps the extension in the catalog but stops the guard enforcing it,
// so the status window can list it and let the user turn it back on. It defaults
// to false (enabled), so a config without the field enforces every extension.
type Extension struct {
	// Name is the stable identifier used by select / enable-extension /
	// disable-extension. Label is the friendly display name shown in the status
	// window (falls back to Name when empty).
	Name     string `json:"name,omitempty"`
	Label    string `json:"label,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	Chrome   Target `json:"chrome"`
	Edge     Target `json:"edge"`
	Brave    Target `json:"brave"`
	Firefox  Target `json:"firefox"`
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
// force-installs and locks, plus app-level settings.
type Config struct {
	Extensions []Extension `json:"extensions"`
	// AutoUpdate controls how the service reacts to a newer release:
	// "notify" (default) logs availability, "apply" downloads and installs it
	// silently, "off" disables the periodic check. See UpdateMode. Silent "apply"
	// should wait until the binaries are code-signed (see docs/pc-version.md).
	AutoUpdate string `json:"autoUpdate,omitempty"`
}

// Update modes for Config.AutoUpdate.
const (
	UpdateNotify = "notify"
	UpdateApply  = "apply"
	UpdateOff    = "off"
)

// UpdateMode returns the normalized auto-update mode, defaulting to "notify" when
// unset or unrecognized.
func (c Config) UpdateMode() string {
	switch strings.ToLower(strings.TrimSpace(c.AutoUpdate)) {
	case UpdateApply:
		return UpdateApply
	case UpdateOff:
		return UpdateOff
	default:
		return UpdateNotify
	}
}

// Targets returns every enforced target for a browser kind, one per enabled
// extension (including empty/placeholder targets; callers skip those via
// chromiumForcelistValue / firefoxConfigured). Disabled extensions are omitted,
// so apply/verify/remove never touch an extension the user turned off.
func (c Config) Targets(k Kind) []Target {
	out := make([]Target, 0, len(c.Extensions))
	for _, e := range c.Extensions {
		if e.Disabled {
			continue
		}
		out = append(out, e.Target(k))
	}
	return out
}

// EnableOnly enables exactly the extensions whose Name is in names
// (case-insensitive) and disables the rest, keeping every extension in the
// catalog. An empty names slice enables all. The installer's component picker
// uses this so unchosen extensions stay listed and can be turned on later.
func (c *Config) EnableOnly(names []string) {
	if len(names) == 0 {
		for i := range c.Extensions {
			c.Extensions[i].Disabled = false
		}
		return
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(strings.ToLower(n)); n != "" {
			want[n] = true
		}
	}
	for i := range c.Extensions {
		c.Extensions[i].Disabled = !want[strings.ToLower(c.Extensions[i].Name)]
	}
}

// SetEnabled flips one extension by name (case-insensitive). Returns false if no
// extension has that name.
func (c *Config) SetEnabled(name string, enabled bool) bool {
	name = strings.TrimSpace(strings.ToLower(name))
	for i := range c.Extensions {
		if strings.ToLower(c.Extensions[i].Name) == name {
			c.Extensions[i].Disabled = !enabled
			return true
		}
	}
	return false
}

// Only returns a copy containing just the named extension, forced enabled. Used
// to lift a single extension's browser lock without touching the others.
func (c Config) Only(name string) Config {
	name = strings.TrimSpace(strings.ToLower(name))
	var out Config
	for _, e := range c.Extensions {
		if strings.ToLower(e.Name) == name {
			e.Disabled = false
			out.Extensions = append(out.Extensions, e)
		}
	}
	return out
}

// AnyEnabled reports whether at least one extension is enabled.
func (c Config) AnyEnabled() bool {
	for _, e := range c.Extensions {
		if !e.Disabled {
			return true
		}
	}
	return false
}

// UnmarshalJSON accepts both the current multi-extension shape
// ({"extensions": [...]}) and the legacy single-extension flat shape
// ({"chrome": {...}, "firefox": {...}, ...}), wrapping the latter as one
// extension so an already-deployed config keeps loading after the upgrade.
func (c *Config) UnmarshalJSON(data []byte) error {
	var multi struct {
		Extensions []Extension `json:"extensions"`
		AutoUpdate string      `json:"autoUpdate"`
	}
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	if len(multi.Extensions) > 0 {
		c.Extensions = multi.Extensions
		c.AutoUpdate = multi.AutoUpdate
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
