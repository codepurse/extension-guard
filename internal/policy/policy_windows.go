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

const forcelistSubkey = `ExtensionInstallForcelist`

// appPathExe is the executable name used to detect each browser via the
// Windows "App Paths" registry.
var appPathExe = map[Kind]string{
	Chrome:  "chrome.exe",
	Edge:    "msedge.exe",
	Brave:   "brave.exe",
	Firefox: "firefox.exe",
	Zen:     "zen.exe",
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
	for _, g := range geckoBrowsers() {
		if err := applyGecko(g, cfg.Targets(g.Kind)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", g.Kind, err))
		}
		if err := removeGecko(g, cfg.InactiveTargets(g.Kind)); err != nil {
			errs = append(errs, fmt.Sprintf("%s prune: %v", g.Kind, err))
		}
	}
	// The forcelist lives in the same hive as the URL filter and is read the same
	// way, so it needs the same nudge. Best effort for the same reason - see
	// gprefresh_windows.go.
	_ = refreshBrowserPolicy()
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

func applyGecko(g GeckoBrowser, targets []Target) error {
	for _, t := range configuredFirefox(targets) {
		path := g.Root + `\ExtensionSettings\` + t.AddonID
		// Skipping a key that is already correct is not just tidiness. Apply runs on
		// every reconcile cycle, and rewriting these values each time would trip the
		// guard's own tamper watcher and make every write look like a policy change
		// that needs a group policy refresh.
		if firefoxEntryCorrect(path, t.InstallURL) {
			continue
		}
		key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
		if err != nil {
			return err
		}
		markBrowserPolicyChanged()
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

// firefoxEntryCorrect reports whether the ExtensionSettings key at path already
// force-installs installURL, so applyGecko can leave it alone.
func firefoxEntryCorrect(path, installURL string) bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	mode, _, _ := key.GetStringValue("installation_mode")
	url, _, _ := key.GetStringValue("install_url")
	return mode == "force_installed" && url == installURL
}

// Verify reports the lock status of each browser. A browser is Locked only when
// every extension configured for it is force-installed.
func Verify(cfg Config) []Status {
	installed := DetectBrowsers()
	gecko := geckoBrowsers()
	out := make([]Status, 0, len(ChromiumKinds)+len(gecko))
	for _, k := range ChromiumKinds {
		out = append(out, verifyChromium(k, cfg.Targets(k), installed[k]))
	}
	for _, g := range gecko {
		out = append(out, verifyGecko(g, cfg.Targets(g.Kind), installed[g.Kind]))
	}
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

func verifyGecko(g GeckoBrowser, targets []Target, installed bool) Status {
	s := Status{Kind: g.Kind, Installed: installed}
	configured := configuredFirefox(targets)
	if len(configured) == 0 {
		return lockStatus(s, 0, 0)
	}
	matched := 0
	for _, t := range configured {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, g.Root+`\ExtensionSettings\`+t.AddonID, registry.QUERY_VALUE)
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
	for _, g := range geckoBrowsers() {
		if err := removeGecko(g, cfg.Targets(g.Kind)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", g.Kind, err))
		}
	}
	_ = refreshBrowserPolicy()
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func removeChromium(k Kind, targets []Target) error {
	return syncNumberedList(chromiumPolicyRoot[k]+`\`+forcelistSubkey, nil, dropForcelist(targets))
}

func removeGecko(g GeckoBrowser, targets []Target) error {
	for _, t := range targets {
		if t.AddonID == "" {
			continue
		}
		// DeleteKey removes the leaf key (installation_mode / install_url values
		// live directly under it). Absence is treated as success - and is also the
		// case where nothing changed, so it asks for no refresh.
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, g.Root+`\ExtensionSettings\`+t.AddonID); err == nil {
			markBrowserPolicyChanged()
		}
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
	// A discovered fork needs no App Paths entry to be known present: it was found
	// by reading a registration that named a file that is there, which is a
	// stronger statement than the one App Paths makes. Without this every
	// discovered browser would show as absent in the row written for it.
	for _, g := range geckoBrowsers() {
		if _, builtin := appPathExe[g.Kind]; !builtin {
			out[g.Kind] = true
		}
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
