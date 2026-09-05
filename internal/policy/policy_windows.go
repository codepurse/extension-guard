//go:build windows

package policy

import (
	"fmt"
	"sort"
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

// geckoPrivateBrowsingValue is the one ExtensionSettings member that closes the
// hole hardening.go exists for, in the Firefox family only: an add-on the guard
// force-installs is still absent from a private window unless this says
// otherwise, so without it "locked" means locked in ordinary windows and nowhere
// else. Mozilla added it in Firefox 136 and ESR 128.8.
//
// Two facts make it safe to write unconditionally. Mozilla's policy engine reads
// a registry DWORD as the boolean the schema asks for - the same encoding
// DisablePrivateBrowsing already uses here - and it validates the members its
// schema names rather than rejecting an object for carrying one it does not
// know, so an older Firefox ignores this and force-installs exactly as before.
const geckoPrivateBrowsingValue = "private_browsing"

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
		if err := applyChromium(k, cfg.Targets(k), cfg.InactiveTargets(k), forgottenIDs(cfg, k)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	for _, g := range geckoBrowsers() {
		if err := applyGecko(g, cfg.Targets(g.Kind)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", g.Kind, err))
		}
		if err := removeGecko(g, cfg.InactiveTargets(g.Kind), forgottenIDs(cfg, g.Kind)); err != nil {
			errs = append(errs, fmt.Sprintf("%s prune: %v", g.Kind, err))
		}
	}
	// After the reconcile, so an id just pruned leaves the record with it and the
	// next pass has no reason to look at it again. See written_windows.go.
	recordWrittenTargets(cfg)
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
func applyChromium(k Kind, want, inactive []Target, forgotten []string) error {
	// The forcelist is not the only way this browser can be pinning an extension,
	// so switching one off has to reach both. Doing only the list is what left an
	// extension force-installed and unremovable while the window reported it as
	// off - a false claim, not merely an incomplete one.
	//
	// The rule is the one dropForcelist already applies: an id the config names and
	// has switched off is the guard's to clear, whoever wrote the entry. An id the
	// config does not name is not, and stays - Status.Foreign is how that gets
	// said instead.
	dropChromiumSettingsPins(k, append(targetIDs(inactive), forgotten...))
	return syncNumberedList(
		chromiumPolicyRoot[k]+`\`+forcelistSubkey,
		chromiumForcelistValues(want),
		dropForcelist(inactive, forgotten),
	)
}

// targetIDs is the extension id of each target, skipping the empty ones.
func targetIDs(targets []Target) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.ExtensionID != "" {
			out = append(out, t.ExtensionID)
		}
	}
	return out
}

// dropChromiumSettingsPins deletes the ExtensionSettings key for each id, in both
// registry views, so an extension switched off stops being force-installed by the
// other policy too.
//
// Best effort and deliberately quiet: a missing key is the ordinary case (the
// guard does not write these, so most machines have none), and a delete that
// fails must not turn applying the forcelist into an error when the forcelist
// itself is fine.
func dropChromiumSettingsPins(k Kind, ids []string) {
	root, ok := chromiumPolicyRoot[k]
	if !ok || len(ids) == 0 {
		return
	}
	for _, base := range []string{root, `SOFTWARE\WOW6432Node\` + strings.TrimPrefix(root, `SOFTWARE\`)} {
		for _, id := range ids {
			if id == "" {
				continue
			}
			if err := registry.DeleteKey(registry.LOCAL_MACHINE, base+`\ExtensionSettings\`+id); err == nil {
				markBrowserPolicyChanged()
			}
		}
	}
}

// dropForcelist reports which forcelist entries belong to the given targets.
// Entries are "<id>;<update_url>", so the extension id prefix identifies ours
// without depending on the update URL still matching what we would write today.
//
// forgotten carries the other kind of entry that is ours: an id the guard wrote
// under an older config which no longer names it. Without it those entries are
// indistinguishable from an administrator's own policy and are kept for ever,
// which is how an extension nobody had configured for months stayed
// force-installed. See written_windows.go.
func dropForcelist(targets []Target, forgotten []string) func(string) bool {
	prefixes := make([]string, 0, len(targets)+len(forgotten))
	for _, t := range targets {
		if t.ExtensionID != "" {
			prefixes = append(prefixes, t.ExtensionID+";")
		}
	}
	for _, id := range forgotten {
		if id != "" {
			prefixes = append(prefixes, id+";")
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
		if err := key.SetDWordValue(geckoPrivateBrowsingValue, 1); err != nil {
			key.Close()
			return err
		}
		key.Close()
	}
	return nil
}

// firefoxEntryCorrect reports whether the ExtensionSettings key at path already
// force-installs installURL into every window, so applyGecko can leave it alone.
//
// private_browsing counts towards "correct" rather than being written once and
// forgotten, and that is what makes it tamper-proof for free: deleting the value
// leaves the add-on installed and silently absent from private windows, which
// this would otherwise read as a key that is already right. Saying it here costs
// one rewrite on the upgrade that introduces it, on a machine that already had
// the entry.
func firefoxEntryCorrect(path, installURL string) bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	mode, _, _ := key.GetStringValue("installation_mode")
	url, _, _ := key.GetStringValue("install_url")
	if private, _, err := key.GetIntegerValue(geckoPrivateBrowsingValue); err != nil || private != 1 {
		return false
	}
	return mode == "force_installed" && url == installURL
}

// Verify reports the lock status of each browser. A browser is Locked only when
// every extension configured for it is force-installed.
func Verify(cfg Config) []Status {
	installed := DetectBrowsers()
	gecko := geckoBrowsers()
	out := make([]Status, 0, len(ChromiumKinds)+len(gecko))
	for _, k := range ChromiumKinds {
		out = append(out, verifyChromium(k, cfg.Targets(k), installed[k], managedIDs(cfg, k)))
	}
	for _, g := range gecko {
		out = append(out, verifyGecko(g, cfg.Targets(g.Kind), installed[g.Kind]))
	}
	return out
}

func verifyChromium(k Kind, targets []Target, installed bool, managed []string) Status {
	s := Status{Kind: k, Installed: installed}

	// Read the other policy first, because it decides both halves of this answer:
	// whether a configured extension is pinned, and whether anything the guard does
	// not manage is.
	pinned := settingsPins(k)
	known := make(map[string]bool, len(managed))
	for _, id := range managed {
		known[id] = true
	}
	for id := range pinned {
		if !known[id] {
			s.Foreign = append(s.Foreign, id)
		}
	}
	sort.Strings(s.Foreign)

	wants := chromiumForcelistValues(targets)
	if len(wants) == 0 {
		return lockStatusExt(s, 0, 0, len(targets))
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
		// Either policy pins it, so either one counts. Reading only the forcelist is
		// what let an extension sit force-installed through a status window
		// reporting the browser as carrying nothing.
		//
		// The id comes out of the entry rather than from targets[i]: wants is the
		// filtered list, so a target skipped for being incomplete shifts every index
		// after it and the pin check would be asking about the wrong extension. The
		// entry is "<id>;<update_url>" by construction, so splitting it is exact.
		id := w
		if i := strings.IndexByte(w, ';'); i >= 0 {
			id = w[:i]
		}
		if present[w] || pinned[id] {
			matched++
		}
	}
	return lockStatusExt(s, matched, len(wants), len(targets))
}

// Behind a var so a test can describe a machine's pins without touching the
// registry - the seam trust.go and gprefresh_windows.go use, for the reason.
var settingsPins = chromiumSettingsPins

// chromiumSettingsPins is every extension id this browser force-installs through
// the ExtensionSettings policy, which is the other way to pin one and the one the
// guard does not write for Chromium.
//
// It exists because the two policies are independent. Emptying the forcelist
// leaves an ExtensionSettings pin untouched, and the extension stays installed
// and unremovable - so a guard that reads only the forcelist reports a browser as
// clear while the browser disagrees, and Remove hands a machine back with an
// extension still pinned that nothing in the app can lift.
//
// Both registry views are read: policy written by a 32-bit tool lands in the
// WOW6432Node mirror, and Chromium reads both.
func chromiumSettingsPins(k Kind) map[string]bool {
	out := map[string]bool{}
	root, ok := chromiumPolicyRoot[k]
	if !ok {
		return out
	}
	for _, base := range []string{root, `SOFTWARE\WOW6432Node\` + strings.TrimPrefix(root, `SOFTWARE\`)} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\ExtensionSettings`, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		ids, _ := key.ReadSubKeyNames(-1)
		key.Close()
		for _, id := range ids {
			sub, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\ExtensionSettings\`+id, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			mode, _, _ := sub.GetStringValue("installation_mode")
			sub.Close()
			if mode == "force_installed" {
				out[id] = true
			}
		}
	}
	return out
}

func verifyGecko(g GeckoBrowser, targets []Target, installed bool) Status {
	s := Status{Kind: g.Kind, Installed: installed}
	configured := configuredFirefox(targets)
	if len(configured) == 0 {
		return lockStatusExt(s, 0, 0, len(targets))
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
	return lockStatusExt(s, matched, len(configured), len(targets))
}

// Remove deletes the force-install policy for every configured extension. It is
// used only on an authorized (password-verified) uninstall.
func Remove(cfg Config) error {
	var errs []string
	// Deliberately config-scoped: this removes what cfg names and nothing else.
	//
	// It must not consult the written record, because "an id my config no longer
	// names" is only a meaningful question of a *complete* config, and Remove
	// cannot tell whether it has one. `disable-extension` hands it cfg.Only(name)
	// - a config carrying exactly one extension - and against that every other id
	// the guard has ever written reads as forgotten. Pruning them would make
	// switching one extension off tear out the rest.
	//
	// Orphans are Apply's business instead, which sees the whole config and runs
	// every reconcile, so one never survives long enough for this to matter.
	for _, k := range ChromiumKinds {
		if err := removeChromium(k, cfg.Targets(k)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	for _, g := range geckoBrowsers() {
		if err := removeGecko(g, cfg.Targets(g.Kind), nil); err != nil {
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
	// Same reasoning as applyChromium: lifting protection has to lift both
	// mechanisms, or an uninstall hands the machine back with the extension still
	// pinned and nothing left running that could remove it.
	dropChromiumSettingsPins(k, targetIDs(targets))
	return syncNumberedList(chromiumPolicyRoot[k]+`\`+forcelistSubkey, nil, dropForcelist(targets, nil))
}

func removeGecko(g GeckoBrowser, targets []Target, forgotten []string) error {
	ids := make([]string, 0, len(targets)+len(forgotten))
	for _, t := range targets {
		ids = append(ids, t.AddonID)
	}
	// An add-on id the guard wrote and the config has since dropped. Unlike the
	// shared forcelist these are keys of their own, so a stale one is not merely
	// kept - it is invisible, since nothing walks ExtensionSettings looking for
	// keys the config does not mention. See written_windows.go.
	ids = append(ids, forgotten...)
	for _, id := range ids {
		if id == "" {
			continue
		}
		// DeleteKey removes the leaf key (installation_mode / install_url values
		// live directly under it). Absence is treated as success - and is also the
		// case where nothing changed, so it asks for no refresh.
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, g.Root+`\ExtensionSettings\`+id); err == nil {
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
