//go:build windows

package policy

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// chromiumPolicyRoot maps each Chromium browser to its policy registry path
// under HKLM. The force-install list lives in the ExtensionInstallForcelist
// subkey beneath it.
var chromiumPolicyRoot = map[Kind]string{
	Chrome: `SOFTWARE\Policies\Google\Chrome`,
	Edge:   `SOFTWARE\Policies\Microsoft\Edge`,
	Brave:  `SOFTWARE\Policies\BraveSoftware\Brave`,
}

const (
	forcelistSubkey   = `ExtensionInstallForcelist`
	firefoxPolicyRoot = `SOFTWARE\Policies\Mozilla\Firefox`
)

// appPathExe is the executable name used to detect each browser via the
// Windows "App Paths" registry.
var appPathExe = map[Kind]string{
	Chrome:  "chrome.exe",
	Edge:    "msedge.exe",
	Brave:   "brave.exe",
	Firefox: "firefox.exe",
}

// Apply reconciles the force-install policy with cfg across every browser:
// every enabled extension is written, and every disabled one is removed.
//
// The removal half matters as much as the write. These mechanisms are
// incremental, so appending the active set would leave a stale entry for
// anything just switched off - and a scheduled extension would stay
// force-installed after its window closed, which is a schedule that can only
// tighten. Extensions/browsers left as placeholders are skipped. Writing keys
// for a browser that isn't installed yet is harmless - the lock takes effect
// if/when that browser appears. Requires Administrator.
func Apply(cfg Config) error {
	var errs []string
	for _, k := range ChromiumKinds {
		if err := applyChromium(k, cfg.Targets(k), cfg.InactiveTargets(k)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	if err := applyFirefox(cfg.Targets(Firefox)); err != nil {
		errs = append(errs, fmt.Sprintf("firefox: %v", err))
	}
	if err := removeFirefox(cfg.InactiveTargets(Firefox)); err != nil {
		errs = append(errs, fmt.Sprintf("firefox prune: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// applyChromium reconciles one browser's forcelist: the enabled extensions are
// present, the disabled ones are gone, and any entry the guard does not manage is
// left in place. See syncNumberedList for why removal has to renumber.
func applyChromium(k Kind, want, inactive []Target) error {
	return syncNumberedList(
		chromiumPolicyRoot[k]+`\`+forcelistSubkey,
		chromiumForcelistValues(want),
		dropForcelist(inactive),
	)
}

// dropForcelist reports which forcelist entries belong to the given targets.
// Entries are "<id>;<update_url>", so the extension id prefix identifies ours
// without depending on the update URL still matching what we would write today.
func dropForcelist(targets []Target) func(string) bool {
	prefixes := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.ExtensionID != "" {
			prefixes = append(prefixes, t.ExtensionID+";")
		}
	}
	if len(prefixes) == 0 {
		return nil
	}
	return func(v string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(v, p) {
				return true
			}
		}
		return false
	}
}

func applyFirefox(targets []Target) error {
	for _, t := range configuredFirefox(targets) {
		key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, firefoxPolicyRoot+`\ExtensionSettings\`+t.AddonID, registry.ALL_ACCESS)
		if err != nil {
			return err
		}
		if err := key.SetStringValue("installation_mode", "force_installed"); err != nil {
			key.Close()
			return err
		}
		if err := key.SetStringValue("install_url", t.InstallURL); err != nil {
			key.Close()
			return err
		}
		key.Close()
	}
	return nil
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
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, chromiumPolicyRoot[k]+`\`+forcelistSubkey, registry.QUERY_VALUE); err == nil {
		names, _ := key.ReadValueNames(-1)
		for _, n := range names {
			if v, _, err := key.GetStringValue(n); err == nil {
				present[v] = true
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

func verifyFirefox(targets []Target, installed bool) Status {
	s := Status{Kind: Firefox, Installed: installed}
	configured := configuredFirefox(targets)
	if len(configured) == 0 {
		return lockStatus(s, 0, 0)
	}
	matched := 0
	for _, t := range configured {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, firefoxPolicyRoot+`\ExtensionSettings\`+t.AddonID, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		mode, _, _ := key.GetStringValue("installation_mode")
		url, _, _ := key.GetStringValue("install_url")
		key.Close()
		if mode == "force_installed" && url == t.InstallURL {
			matched++
		}
	}
	return lockStatus(s, matched, len(configured))
}

// Remove deletes the force-install policy for every configured extension. It is
// used only on an authorized (password-verified) uninstall.
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
	return syncNumberedList(chromiumPolicyRoot[k]+`\`+forcelistSubkey, nil, dropForcelist(targets))
}

func removeFirefox(targets []Target) error {
	for _, t := range targets {
		if t.AddonID == "" {
			continue
		}
		// DeleteKey removes the leaf key (installation_mode / install_url values
		// live directly under it). Absence is treated as success.
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, firefoxPolicyRoot+`\ExtensionSettings\`+t.AddonID)
	}
	return nil
}

// DetectBrowsers reports which supported browsers are installed, using the
// Windows "App Paths" registry (checked in both HKLM and HKCU).
func DetectBrowsers() map[Kind]bool {
	out := make(map[Kind]bool, len(appPathExe))
	for k, exe := range appPathExe {
		out[k] = appPathExists(exe)
	}
	return out
}

func appPathExists(exe string) bool {
	const base = `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\`
	for _, root := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
		if key, err := registry.OpenKey(root, base+exe, registry.QUERY_VALUE); err == nil {
			key.Close()
			return true
		}
	}
	return false
}
