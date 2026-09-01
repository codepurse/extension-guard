//go:build windows

package policy

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// The registry half of hardening.go. Every value here lives under a browser's
// policy root - the same root the force-install list and the URL filter already
// live under, which is what makes this the cheapest enforcement in the guard: the
// tamper watcher is already watching that hive, so a deleted value is restored
// within milliseconds without a line of new code, and nothing here terminates a
// process or writes outside SOFTWARE\Policies. Like domain blocking and unlike app
// blocking, it could ship before the code-signing certificate.
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
	// valFirefoxPrivate is the Firefox family's equivalent of the two Chromium
	// switches at once: there is no guest profile, so private browsing is the whole
	// surface. Mozilla's policy engine reads booleans from the registry as REG_DWORD
	// 0/1, and Zen reads this one from its own root exactly as Firefox does.
	valFirefoxPrivate = "DisablePrivateBrowsing"
)

// The DNS-over-HTTPS names, which are the reason this file carries value types at
// all: everything above is a DWORD directly under the policy root, and none of
// this is.
//
// The two families disagree about more than spelling. Chromium takes a mode word
// and a template, both REG_SZ, and "secure" means DoH only with no fallback -
// Microsoft's own documentation says the template must then be non-empty, which is
// why the two are always written together or not at all. Mozilla takes a subkey
// holding four values of two types, and its no-fallback switch is a separate
// value that only exists from Firefox 124.
const (
	subGeckoDoH = "DNSOverHTTPS"

	valDoHMode      = "DnsOverHttpsMode"
	valDoHTemplates = "DnsOverHttpsTemplates"

	valGeckoDoHEnabled  = "Enabled"
	valGeckoDoHProvider = "ProviderURL"
	valGeckoDoHLocked   = "Locked"
	valGeckoDoHFallback = "Fallback"

	// dohModeSecure is the whole point of the knob: "automatic" falls back to
	// plaintext DNS on any error, which turns "make the resolver unreachable" into
	// a working bypass rather than a broken browser.
	dohModeSecure = "secure"
)

// polRef locates one policy value relative to a browser's policy root. Sub is
// empty for a value directly under the root, which is everything except Mozilla's
// DoH block.
type polRef struct {
	Sub  string
	Name string
}

// polVal is one policy value's contents. IsStr picks which field is meant, so a
// REG_SZ holding "0" is never confused with a REG_DWORD holding zero.
type polVal struct {
	DWord uint32
	Str   string
	IsStr bool
}

func dword(v uint32) polVal { return polVal{DWord: v} }
func sz(s string) polVal    { return polVal{Str: s, IsStr: true} }

// managedValues is every value the guard may write for a browser, mapped to every
// value it may write there.
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
//
// The DoH templates are the one place that compromise is tighter rather than
// looser: only the exact resolver URLs this build knows count as ours, so an
// administrator who had pinned their own resolver keeps it. Losing somebody's
// DnsOverHttpsMode is recoverable; silently repointing their DNS is not.
func managedValues(k Kind, gecko bool) map[polRef][]polVal {
	out := map[polRef][]polVal{}
	at := func(name string, vals ...polVal) { out[polRef{Name: name}] = vals }
	under := func(sub, name string, vals ...polVal) { out[polRef{Sub: sub, Name: name}] = vals }

	if KnobSupported(KnobPrivateBrowsing, k) {
		if gecko {
			at(valFirefoxPrivate, dword(1))
		} else {
			at(valIncognito, dword(1))
			at(valGuestMode, dword(0))
			if k == Brave {
				at(valTorDisabled, dword(1))
			}
		}
	}
	if KnobSupported(KnobSafeSearch, k) {
		at(valGoogleSafe, dword(1))
		at(valYouTubeRestrict, dword(1), dword(2))
		if k == Edge {
			at(valBingSafe, dword(1), dword(2))
		}
	}
	if KnobSupported(KnobDNSFilter, k) {
		templates := make([]polVal, 0, len(Resolvers))
		for _, r := range Resolvers {
			templates = append(templates, sz(r.Template))
		}
		if gecko {
			under(subGeckoDoH, valGeckoDoHEnabled, dword(1))
			under(subGeckoDoH, valGeckoDoHLocked, dword(1))
			under(subGeckoDoH, valGeckoDoHFallback, dword(0))
			out[polRef{Sub: subGeckoDoH, Name: valGeckoDoHProvider}] = templates
		} else {
			at(valDoHMode, sz(dohModeSecure))
			out[polRef{Name: valDoHTemplates}] = templates
		}
	}
	return out
}

// wantedValues is what one browser's policy root should hold right now. An empty
// map means the guard asks nothing of this browser, either because no knob is on
// or because none of the knobs that are on exist for it.
func wantedValues(k Kind, gecko bool, h Hardening) map[polRef]polVal {
	out := map[polRef]polVal{}
	at := func(name string, v polVal) { out[polRef{Name: name}] = v }

	if h.PrivateBrowsing && KnobSupported(KnobPrivateBrowsing, k) {
		if gecko {
			at(valFirefoxPrivate, dword(1))
		} else {
			at(valIncognito, dword(1))
			at(valGuestMode, dword(0))
			if k == Brave {
				at(valTorDisabled, dword(1))
			}
		}
	}
	if level, on := h.SafeSearchOn(); on && KnobSupported(KnobSafeSearch, k) {
		restrict := uint32(2)
		if level == SafeSearchModerate {
			restrict = 1
		}
		at(valGoogleSafe, dword(1))
		at(valYouTubeRestrict, dword(restrict))
		if k == Edge {
			at(valBingSafe, dword(restrict))
		}
	}
	if r, on := h.DNSFilterOn(); on && KnobSupported(KnobDNSFilter, k) {
		if gecko {
			// Four values, and each one is load-bearing. Enabled turns DoH on,
			// ProviderURL points it at the filter, Locked stops the user pointing it
			// somewhere else in about:preferences, and Fallback 0 is what makes it
			// fail closed rather than quietly reverting to the machine's resolver.
			out[polRef{Sub: subGeckoDoH, Name: valGeckoDoHEnabled}] = dword(1)
			out[polRef{Sub: subGeckoDoH, Name: valGeckoDoHProvider}] = sz(r.Template)
			out[polRef{Sub: subGeckoDoH, Name: valGeckoDoHLocked}] = dword(1)
			out[polRef{Sub: subGeckoDoH, Name: valGeckoDoHFallback}] = dword(0)
		} else {
			at(valDoHMode, sz(dohModeSecure))
			at(valDoHTemplates, sz(r.Template))
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
	for _, t := range policyTargets() {
		if err := syncPolicyValues(t.Root, wantedValues(t.Kind, t.Gecko, h), managedValues(t.Kind, t.Gecko)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", t.Kind, err))
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
	targets := policyTargets()
	out := make([]Status, 0, len(targets))
	for _, t := range targets {
		out = append(out, verifyHardeningOne(
			Status{Kind: t.Kind, Installed: installed[t.Kind]},
			t.Root,
			wantedValues(t.Kind, t.Gecko, h),
			h.Any(),
		))
	}
	return out
}

// verifyHardeningOne tallies one browser. The "not available" case is the one
// worth the extra branch: a config with only SafeSearch on asks nothing of
// Firefox, and reporting that as "not configured" would read as "nobody asked",
// when in fact somebody asked and Firefox cannot do it.
func verifyHardeningOne(s Status, root string, want map[polRef]polVal, asked bool) Status {
	if len(want) == 0 {
		if asked {
			s.Detail = "not available in " + string(s.Kind)
			return s
		}
		return lockStatus(s, 0, 0)
	}
	current := readPolicyValues(root, want)
	matched := 0
	for ref, wantVal := range want {
		if cur, ok := current[ref]; ok && cur == wantVal {
			matched++
		}
	}
	return lockStatus(s, matched, len(want))
}

// RemoveHardening clears every value the guard manages here, whatever the config
// currently asks for. Used on an authorized teardown and on the start of a pause -
// a pause has to hand Incognito back, or protection being off would not be off.
func RemoveHardening(cfg Config) error {
	var errs []string
	for _, t := range policyTargets() {
		if err := syncPolicyValues(t.Root, nil, managedValues(t.Kind, t.Gecko)); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", t.Kind, err))
		}
	}
	_ = refreshBrowserPolicy()
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// syncPolicyValues reconciles the policy values under root so that afterwards
// every ref in want holds its value, every managed ref that is not wanted and
// still holds one of the guard's own values is gone, and everything else under the
// key is untouched.
//
// It opens a key for writing only when something actually has to change. Apply
// runs on every reconcile cycle - startup, tamper, the backstop timer, every
// schedule boundary - so rewriting these values each time would mark the browser
// policy dirty forever and ask Windows for a machine-wide policy refresh every
// few seconds to confirm that nothing had changed. It also means a browser the
// config says nothing about never has a key created for it, which now extends to
// subkeys: a machine with the DNS filter off never grows a DNSOverHTTPS key.
func syncPolicyValues(root string, want map[polRef]polVal, managed map[polRef][]polVal) error {
	current := readPolicyValues(root, managed)

	writes := map[polRef]polVal{}
	for ref, val := range want {
		if cur, ok := current[ref]; !ok || cur != val {
			writes[ref] = val
		}
	}
	deletes := map[polRef]bool{}
	for ref, ours := range managed {
		if _, keep := want[ref]; keep {
			continue
		}
		cur, ok := current[ref]
		if !ok {
			continue
		}
		for _, o := range ours {
			if cur == o {
				deletes[ref] = true
				break
			}
		}
	}
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}

	// Grouped by subkey so each one is opened once, and so a subkey with nothing
	// to do is not created just because its parent had a write.
	for _, sub := range subKeysTouched(writes, deletes) {
		if err := syncOneKey(root, sub, writes, deletes); err != nil {
			return err
		}
	}
	return nil
}

// subKeysTouched lists the distinct subkeys the pending changes land in, with the
// root itself first so a fresh policy root exists before a subkey is created
// under it.
func subKeysTouched(writes map[polRef]polVal, deletes map[polRef]bool) []string {
	seen := map[string]bool{}
	var out []string
	add := func(sub string) {
		if seen[sub] {
			return
		}
		seen[sub] = true
		if sub == "" {
			out = append([]string{sub}, out...)
			return
		}
		out = append(out, sub)
	}
	for ref := range writes {
		add(ref.Sub)
	}
	for ref := range deletes {
		add(ref.Sub)
	}
	return out
}

// syncOneKey applies the writes and deletes that belong to one key.
func syncOneKey(root, sub string, writes map[polRef]polVal, deletes map[polRef]bool) error {
	path := keyPath(root, sub)
	mine := func(ref polRef) bool { return ref.Sub == sub }

	any := false
	for ref := range writes {
		if mine(ref) {
			any = true
			break
		}
	}
	if !any {
		for ref := range deletes {
			if mine(ref) {
				any = true
				break
			}
		}
	}
	if !any {
		return nil
	}

	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	// Next to the write itself, for the reason writeNumberedList marks it there: a
	// policy added later cannot forget to ask for the refresh.
	markBrowserPolicyChanged()

	for ref, val := range writes {
		if !mine(ref) {
			continue
		}
		if err := setPolicyValue(key, ref.Name, val); err != nil {
			key.Close()
			return err
		}
	}
	for ref := range deletes {
		if !mine(ref) {
			continue
		}
		if err := key.DeleteValue(ref.Name); err != nil && err != registry.ErrNotExist {
			key.Close()
			return err
		}
	}
	key.Close()

	// A subkey the guard created and has now emptied is removed, so an authorized
	// teardown leaves the hive as it found it. Only when it is genuinely empty:
	// Mozilla's DNSOverHTTPS block can also hold an administrator's ExcludedDomains,
	// and deleting a key because our four values left would take theirs with it.
	if sub != "" {
		pruneEmptyKey(path)
	}
	return nil
}

func setPolicyValue(key registry.Key, name string, val polVal) error {
	if val.IsStr {
		return key.SetStringValue(name, val.Str)
	}
	return key.SetDWordValue(name, val.DWord)
}

func keyPath(root, sub string) string {
	if sub == "" {
		return root
	}
	return root + `\` + sub
}

// pruneEmptyKey deletes path if it holds no values and no subkeys. Best-effort
// throughout: this is tidiness, and every failure mode leaves behind an empty key
// that enforces nothing.
func pruneEmptyKey(path string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	names, errN := key.ReadValueNames(-1)
	subs, errS := key.ReadSubKeyNames(-1)
	key.Close()
	if errN != nil || errS != nil || len(names) > 0 || len(subs) > 0 {
		return
	}
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, path)
}

// readPolicyValues reads the refs that are present under root, typed the way the
// caller expects them. A missing key reads as an absent value rather than an
// error, exactly as a missing numbered list does.
//
// The expected type comes from the caller's own map, which is what makes a
// REG_DWORD sitting where a REG_SZ belongs read as absent rather than as a match:
// it is not a value this guard would have written, so it is not one it should
// claim or clear.
func readPolicyValues[T any](root string, expect map[polRef]T) map[polRef]polVal {
	out := make(map[polRef]polVal, len(expect))
	byKey := map[string][]polRef{}
	for ref := range expect {
		byKey[ref.Sub] = append(byKey[ref.Sub], ref)
	}
	for sub, refs := range byKey {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath(root, sub), registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		for _, ref := range refs {
			if v, ok := readOne(key, ref.Name, wantsString(expect[ref])); ok {
				out[ref] = v
			}
		}
		key.Close()
	}
	return out
}

// wantsString reports whether the expected value for a ref is a REG_SZ. The two
// map shapes this is asked about - one value, or every value the guard accepts -
// agree on the type, so the first entry answers for a slice.
func wantsString(expect any) bool {
	switch v := expect.(type) {
	case polVal:
		return v.IsStr
	case []polVal:
		return len(v) > 0 && v[0].IsStr
	}
	return false
}

func readOne(key registry.Key, name string, wantStr bool) (polVal, bool) {
	if wantStr {
		s, _, err := key.GetStringValue(name)
		if err != nil {
			return polVal{}, false
		}
		return sz(s), true
	}
	v, _, err := key.GetIntegerValue(name)
	if err != nil {
		return polVal{}, false
	}
	return dword(uint32(v)), true
}
