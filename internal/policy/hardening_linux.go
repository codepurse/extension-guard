//go:build linux

package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The Linux half of hardening.go. Same settings, same knobSupport table, written
// as managed policy JSON instead of registry DWORDs.
//
// hardeningPolicyFileName is a third file, separate from the extension and domain
// ones, for the reason stated in urlblock_linux.go: Chromium merges every JSON
// file in the managed directory and each enforcer rewrites its own file
// wholesale, so sharing one would mean whichever ran second erased the other's
// policy.
const hardeningPolicyFileName = "extension-guard-hardening.json"

// chromiumHardeningKeys is every key the guard may write for a Chromium browser.
// It exists for removal: the guard owns its own policy file outright, so clearing
// it is a file delete, but Firefox's document is shared and has to be edited key
// by key.
const firefoxPrivateKey = "DisablePrivateBrowsing"

// chromiumHardeningDoc is what one Chromium browser's policy file should contain.
// An empty map means the guard asks nothing of this browser - either no knob is on
// or none of the ones that are exist for it - and the file is removed rather than
// written empty.
//
// The JSON types are not the registry's. A managed policy file is read as JSON, so
// a boolean policy is a boolean and an enumerated one is a number; writing 1 for
// BrowserGuestModeEnabled would be a type error Chromium discards the whole file
// over.
func chromiumHardeningDoc(k Kind, h Hardening) map[string]any {
	doc := map[string]any{}
	if h.PrivateBrowsing && KnobSupported(KnobPrivateBrowsing, k) {
		doc["IncognitoModeAvailability"] = 1
		doc["BrowserGuestModeEnabled"] = false
		if k == Brave {
			doc["TorDisabled"] = true
		}
	}
	if level, on := h.SafeSearchOn(); on && KnobSupported(KnobSafeSearch, k) {
		restrict := 2
		if level == SafeSearchModerate {
			restrict = 1
		}
		doc["ForceGoogleSafeSearch"] = true
		doc["ForceYouTubeRestrict"] = restrict
		if k == Edge {
			doc["ForceBingSafeSearch"] = restrict
		}
	}
	return doc
}

// ApplyHardening reconciles every browser's hardening policy with cfg. Requires
// root.
func ApplyHardening(cfg Config) error {
	h := cfg.Hardened()
	var errs []string
	for _, k := range ChromiumKinds {
		if err := applyChromiumHardening(k, h); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	if err := applyFirefoxHardening(h); err != nil {
		errs = append(errs, fmt.Sprintf("firefox: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// applyChromiumHardening writes the wanted document wholesale, which reconciles by
// construction. Nothing wanted clears a file we previously wrote - a knob turned
// off has to stop being enforced - but does not create one where none existed.
func applyChromiumHardening(k Kind, h Hardening) error {
	dir := chromiumManagedDir[k]
	path := filepath.Join(dir, hardeningPolicyFileName)
	doc := chromiumHardeningDoc(k, h)
	if len(doc) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// applyFirefoxHardening merges into the shared policies.json, touching only the
// one key it owns, so the extension enforcer's ExtensionSettings and the domain
// enforcer's WebsiteFilter survive a cycle in which all three run.
//
// Firefox is absent from knobSupport for safe-search, so this only ever has
// private browsing to write.
func applyFirefoxHardening(h Hardening) error {
	path := firefoxPoliciesPath()
	want := h.PrivateBrowsing && KnobSupported(KnobPrivateBrowsing, Firefox)
	if !want {
		if _, err := os.Stat(path); err != nil {
			return nil
		}
	}
	if err := os.MkdirAll(firefoxPoliciesDir, 0o755); err != nil {
		return err
	}
	doc := readFirefoxDoc()
	policies := childMap(doc, "policies")
	if want {
		policies[firefoxPrivateKey] = true
	} else {
		delete(policies, firefoxPrivateKey)
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// VerifyHardening reports, per browser, whether every setting the hardening asks
// for is present and correct.
func VerifyHardening(cfg Config) []Status {
	h := cfg.Hardened()
	installed := DetectBrowsers()
	out := make([]Status, 0, len(ChromiumKinds)+1)
	for _, k := range ChromiumKinds {
		out = append(out, verifyChromiumHardening(k, h, installed[k]))
	}
	out = append(out, verifyFirefoxHardening(h, installed[Firefox]))
	return out
}

func verifyChromiumHardening(k Kind, h Hardening, installed bool) Status {
	s := Status{Kind: k, Installed: installed}
	want := chromiumHardeningDoc(k, h)
	if len(want) == 0 {
		return notAvailableOr(s, h.Any())
	}
	present := map[string]any{}
	if data, err := os.ReadFile(filepath.Join(chromiumManagedDir[k], hardeningPolicyFileName)); err == nil {
		_ = json.Unmarshal(data, &present)
	}
	matched := 0
	for name, val := range want {
		// Compared through JSON rather than by ==: a number that went through
		// encoding/json comes back as float64, so 1 and 1.0 are the same setting and
		// a direct comparison against the int literal above would never match.
		if sameJSON(present[name], val) {
			matched++
		}
	}
	return lockStatus(s, matched, len(want))
}

func verifyFirefoxHardening(h Hardening, installed bool) Status {
	s := Status{Kind: Firefox, Installed: installed}
	if !(h.PrivateBrowsing && KnobSupported(KnobPrivateBrowsing, Firefox)) {
		return notAvailableOr(s, h.Any())
	}
	var doc struct {
		Policies map[string]any `json:"policies"`
	}
	if data, err := os.ReadFile(firefoxPoliciesPath()); err == nil {
		_ = json.Unmarshal(data, &doc)
	}
	matched := 0
	if v, ok := doc.Policies[firefoxPrivateKey].(bool); ok && v {
		matched = 1
	}
	return lockStatus(s, matched, 1)
}

// notAvailableOr distinguishes "nobody asked" from "somebody asked and this
// browser cannot do it" - see verifyHardeningOne in hardening_windows.go for why
// that distinction is worth a branch.
func notAvailableOr(s Status, asked bool) Status {
	if asked {
		s.Detail = "not available in " + string(s.Kind)
		return s
	}
	return lockStatus(s, 0, 0)
}

func sameJSON(a, b any) bool {
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(ab) == string(bb)
}

// RemoveHardening clears every setting the guard manages here, whatever the config
// currently asks for. Used on an authorized teardown and at the start of a pause.
func RemoveHardening(cfg Config) error {
	var errs []string
	for _, k := range ChromiumKinds {
		if err := applyChromiumHardening(k, Hardening{}); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", k, err))
		}
	}
	if err := applyFirefoxHardening(Hardening{}); err != nil {
		errs = append(errs, fmt.Sprintf("firefox: %v", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
