//go:build windows

package policy

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// The registry half of hardening.go. Every value here is a DWORD directly under a
// browser's policy root - the same root the force-install list and the URL filter
// already live under, which is what makes this the cheapest enforcement in the
// guard: the tamper watcher is already watching that hive, so a deleted value is
// restored within milliseconds without a line of new code, and nothing here
// terminates a process or writes outside SOFTWARE\Policies. Like domain blocking
// and unlike app blocking, it could ship before the code-signing certificate.
//
// What is verified is that the *policy is written*, not that the browser obeyed
// it. That is true of every policy in this package - the guard cannot see inside
// Chrome - and it is why knobSupport in hardening.go is maintained by hand: a
// value a browser does not implement would verify perfectly and enforce nothing,
// so the only defence is to not claim the ones that do not exist.

// Chromium policy value names. Two per knob, because each knob covers two ways to
// get the same window:
//
//   - IncognitoModeAvailability 1 is "Incognito disabled". Guest mode is a
//     separate switch and needs saying separately, and it matters more: an
//     Incognito window at least belongs to a profile the force-install reached,
//     while a guest session carries no extensions at all.
//   - ForceYouTubeRestrict takes the level (1 moderate, 2 strict); Google and Bing
//     SafeSearch are booleans, and Bing's is Edge-only.
const (
	valIncognito       = "IncognitoModeAvailability"
	valGuestMode       = "BrowserGuestModeEnabled"
	valGoogleSafe      = "ForceGoogleSafeSearch"
	valYouTubeRestrict = "ForceYouTubeRestrict"
	valBingSafe        = "ForceBingSafeSearch"
	// valTorDisabled is Brave's own. Brave's private window has a second form -
	// "New private window with Tor" - which IncognitoModeAvailability does not
	// describe, and leaving it out would close the front door of the one browser
	// that ships a back one.
	valTorDisabled = "TorDisabled"
	// valFirefoxPrivate is Firefox's equivalent of the two Chromium switches at
	// once: Firefox has no guest profile, so private browsing is the whole surface.
	// Firefox reads booleans from the registry as REG_DWORD 0/1.
	valFirefoxPrivate = "DisablePrivateBrowsing"
)

// hardeningRoot is the policy key each browser's values are written under. It is
// the same root the forcelist and URL filter use, one level up from their
// subkeys.
func hardeningRoot(k Kind) string {
	if k == Firefox {
		return firefoxPolicyRoot
	}
	return chromiumPolicyRoot[k]
}

// managedNames is every value name the guard may write for a browser, mapped to
// every DWORD it may write there.
//
// The second half is what makes removal safe. Unlike the forcelist there is no
// prefix identifying an entry as ours, and unlike the URL filter the value is not
// a pattern only this guard would produce - "IncognitoModeAvailability = 1" is
// exactly what an administrator who wanted the same thing would have set. So a
// value only counts as the guard's when it holds one of the values the guard
// writes, which is the same compromise dropExact makes in urlblock_windows.go and
// has the same edge: turning hardening off will clear a setting somebody else had
// already set to the same thing. Erring the other way would leave Incognito
// disabled after an authorized uninstall, which is worse - the machine has to come
// back the way it was.
func managedNames(k Kind) map[string][]uint32 {
	out := map[string][]uint32{}
	if KnobSupported(KnobPrivateBrowsing, k) {
		if k == Firefox {
			out[valFirefoxPrivate] = []uint32{1}
		} else {
			out[valIncognito] = []uint32{1}
			out[valGuestMode] = []uint32{0}
			if k == Brave {
				out[valTorDisabled] = []uint32{1}
			}
		}
	}
	if KnobSupported(KnobSafeSearch, k) {
		out[valGoogleSafe] = []uint32{1}
		out[valYouTubeRestrict] = []uint32{1, 2}
		if k == Edge {
			out[valBingSafe] = []uint32{1, 2}
		}
	}
	return out
}

// wantedValues is what one browser's policy root should hold right now. An empty
// map means the guard asks nothing of this browser, either because no knob is on
// or because none of the knobs that are on exist for it.
func wantedValues(k Kind, h Hardening) map[string]uint32 {
	out := map[string]uint32{}
	if h.PrivateBrowsing && KnobSupported(KnobPrivateBrowsing, k) {
		if k == Firefox {
			out[valFirefoxPrivate] = 1
		} else {
			out[valIncognito] = 1
			out[valGuestMode] = 0
			if k == Brave {
				out[valTorDisabled] = 1
			}
		}
	}
	if level, on := h.SafeSearchOn(); on && KnobSupported(KnobSafeSearch, k) {
		restrict := uint32(2)
		if level == SafeSearchModerate {
			restrict = 1
		}
		out[valGoogleSafe] = 1
		out[valYouTubeRestrict] = restrict
		if k == Edge {
			out[valBingSafe] = restrict
		}
	}
	return out
}

// ApplyHardening reconciles every browser's policy root with the hardening cfg
// asks for: the values for each knob that is on are written, the values for a
// knob that has been turned off are cleared, and anything else under the key is
// left alone. Requires Administrator.
func ApplyHardening(cfg Config) error {
	h := cfg.Hardened()
	var errs []string
	for _, k := range append(append([]Kind{}, ChromiumKinds...), Firefox) {
		if err := syncPolicyValues(hardeningRoot(k), wantedValues(k, h), managedNames(k)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	// Same reason as ApplyDomains: a running Chromium will not see any of this
	// until group policy is refreshed, and a refresh that fails must not turn a
	// setting that *was* written into an apply failure. Firefox reads its policies
	// only at startup and has no reload path at all - see gprefresh_windows.go.
	_ = refreshBrowserPolicy()
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// VerifyHardening reports, per browser, whether every value the hardening asks
// for is present and correct. Read-only, so it works unelevated from the status
// window.
func VerifyHardening(cfg Config) []Status {
	h := cfg.Hardened()
	installed := DetectBrowsers()
	kinds := append(append([]Kind{}, ChromiumKinds...), Firefox)
	out := make([]Status, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, verifyHardeningOne(
			Status{Kind: k, Installed: installed[k]},
			hardeningRoot(k),
			wantedValues(k, h),
			h.Any(),
		))
	}
	return out
}

// verifyHardeningOne tallies one browser. The "not available" case is the one
// worth the extra branch: a config with only SafeSearch on asks nothing of
// Firefox, and reporting that as "not configured" would read as "nobody asked",
// when in fact somebody asked and Firefox cannot do it.
func verifyHardeningOne(s Status, root string, want map[string]uint32, asked bool) Status {
	if len(want) == 0 {
		if asked {
			s.Detail = "not available in " + string(s.Kind)
			return s
		}
		return lockStatus(s, 0, 0)
	}
	matched := 0
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.QUERY_VALUE); err == nil {
		for name, wantVal := range want {
			if cur, _, err := key.GetIntegerValue(name); err == nil && uint32(cur) == wantVal {
				matched++
			}
		}
		key.Close()
	}
	return lockStatus(s, matched, len(want))
}

// RemoveHardening clears every value the guard manages here, whatever the config
// currently asks for. Used on an authorized teardown and on the start of a pause -
// a pause has to hand Incognito back, or protection being off would not be off.
func RemoveHardening(cfg Config) error {
	var errs []string
	for _, k := range append(append([]Kind{}, ChromiumKinds...), Firefox) {
		if err := syncPolicyValues(hardeningRoot(k), nil, managedNames(k)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	_ = refreshBrowserPolicy()
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// syncPolicyValues reconciles the DWORD policy values under path so that
// afterwards every name in want holds its value, every managed name that is not
// wanted and still holds one of the guard's own values is gone, and everything
// else under the key is untouched.
//
// It opens the key for writing only when something actually has to change. Apply
// runs on every reconcile cycle - startup, tamper, the backstop timer, every
// schedule boundary - so rewriting these values each time would mark the browser
// policy dirty forever and ask Windows for a machine-wide policy refresh every
// few seconds to confirm that nothing had changed. It also means a browser the
// config says nothing about never has a key created for it.
func syncPolicyValues(path string, want map[string]uint32, managed map[string][]uint32) error {
	current := readPolicyValues(path, managed)

	writes := map[string]uint32{}
	for name, val := range want {
		if cur, ok := current[name]; !ok || cur != val {
			writes[name] = val
		}
	}
	var deletes []string
	for name, ours := range managed {
		if _, keep := want[name]; keep {
			continue
		}
		cur, ok := current[name]
		if !ok {
			continue
		}
		for _, o := range ours {
			if cur == o {
				deletes = append(deletes, name)
				break
			}
		}
	}
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}

	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()
	// Next to the write itself, for the reason writeNumberedList marks it there: a
	// policy added later cannot forget to ask for the refresh.
	markBrowserPolicyChanged()

	for name, val := range writes {
		if err := key.SetDWordValue(name, val); err != nil {
			return err
		}
	}
	for _, name := range deletes {
		if err := key.DeleteValue(name); err != nil && err != registry.ErrNotExist {
			return err
		}
	}
	return nil
}

// readPolicyValues reads the managed value names that are present under path. A
// missing key reads as an empty map rather than an error, exactly as a missing
// numbered list does.
func readPolicyValues(path string, managed map[string][]uint32) map[string]uint32 {
	out := make(map[string]uint32, len(managed))
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer key.Close()
	for name := range managed {
		if v, _, err := key.GetIntegerValue(name); err == nil {
			out[name] = uint32(v)
		}
	}
	return out
}
