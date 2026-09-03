//go:build windows

package policy

import "testing"

// ref and gref name a policy value the way the writer does: most sit directly
// under a browser's policy root, and Mozilla's DoH block sits in a subkey.
func ref(name string) polRef  { return polRef{Name: name} }
func gref(name string) polRef { return polRef{Sub: subGeckoDoH, Name: name} }

// TestWantedValuesPerBrowser pins the values each browser gets, because a wrong
// value here verifies perfectly and enforces nothing - the guard can only see that
// it wrote what it meant to write, never that the browser obeyed.
func TestWantedValuesPerBrowser(t *testing.T) {
	private := Hardening{PrivateBrowsing: true}

	for _, k := range ChromiumKinds {
		got := wantedValues(k, false, private)
		if got[ref(valIncognito)] != dword(1) {
			t.Errorf("%s: %s = %v, want 1", k, valIncognito, got[ref(valIncognito)])
		}
		// Guest mode is the bigger hole of the two: a guest session carries no
		// extensions at all, so it has to be named separately from Incognito.
		if v, ok := got[ref(valGuestMode)]; !ok || v != dword(0) {
			t.Errorf("%s: %s = %v (present %v), want 0", k, valGuestMode, v, ok)
		}
	}
	// Brave's private window has a second form the Chromium switch does not
	// describe.
	if _, ok := wantedValues(Brave, false, private)[ref(valTorDisabled)]; !ok {
		t.Errorf("brave: %s not written, so \"private window with Tor\" stays open", valTorDisabled)
	}
	if _, ok := wantedValues(Chrome, false, private)[ref(valTorDisabled)]; ok {
		t.Errorf("chrome: %s written, which is a Brave-only policy", valTorDisabled)
	}
	// The whole family, not Firefox alone: a fork reads the same policy from its
	// own root, and one left out of this would show private browsing as pinned
	// while its private window still opened - with none of the locked extensions
	// in it, which is the case the knob exists for.
	for _, k := range GeckoKinds {
		if got := wantedValues(k, true, private); got[ref(valFirefoxPrivate)] != dword(1) {
			t.Errorf("%s: %s = %v, want 1", k, valFirefoxPrivate, got[ref(valFirefoxPrivate)])
		}
		if _, ok := wantedValues(k, true, private)[ref(valIncognito)]; ok {
			t.Errorf("%s: %s written, which is a Chromium policy", k, valIncognito)
		}
	}

	strict := Hardening{SafeSearch: SafeSearchStrict}
	moderate := Hardening{SafeSearch: SafeSearchModerate}
	for _, k := range ChromiumKinds {
		if got := wantedValues(k, false, strict); got[ref(valGoogleSafe)] != dword(1) || got[ref(valYouTubeRestrict)] != dword(2) {
			t.Errorf("%s strict: google=%v youtube=%v, want 1 and 2", k, got[ref(valGoogleSafe)], got[ref(valYouTubeRestrict)])
		}
		if got := wantedValues(k, false, moderate); got[ref(valYouTubeRestrict)] != dword(1) {
			t.Errorf("%s moderate: youtube=%v, want 1", k, got[ref(valYouTubeRestrict)])
		}
	}
	if _, ok := wantedValues(Edge, false, strict)[ref(valBingSafe)]; !ok {
		t.Errorf("edge: %s not written, so Bing is unfiltered in the browser that defaults to it", valBingSafe)
	}
	if _, ok := wantedValues(Chrome, false, strict)[ref(valBingSafe)]; ok {
		t.Errorf("chrome: %s written, which is an Edge-only policy", valBingSafe)
	}
	// Firefox has no SafeSearch policy, so it must be asked for nothing rather than
	// handed a value that does nothing. knobSupport is the single source for that,
	// and this is what holds the writer to it.
	for _, k := range GeckoKinds {
		if got := wantedValues(k, true, strict); len(got) != 0 {
			t.Errorf("%s safe-search wrote %v, want nothing", k, got)
		}
	}
}

// TestWantedValuesPinTheResolverFailClosed is the DNS filter's own pinning, and
// every assertion here is about the knob failing closed rather than about it being
// configured. A resolver that is merely preferred is not a filter: "automatic"
// mode and Mozilla's Fallback both mean the browser quietly returns to the
// machine's resolver the moment the filtered one errors, which turns "make
// Cloudflare unreachable" into a working bypass.
func TestWantedValuesPinTheResolverFailClosed(t *testing.T) {
	want, ok := LookupResolver(ResolverCloudflareFamily)
	if !ok {
		t.Fatal("the default resolver is missing from the table")
	}
	h := Hardening{DNSFilter: ResolverCloudflareFamily}

	for _, k := range ChromiumKinds {
		got := wantedValues(k, false, h)
		if got[ref(valDoHMode)] != sz(dohModeSecure) {
			t.Errorf("%s: %s = %v, want %q", k, valDoHMode, got[ref(valDoHMode)], dohModeSecure)
		}
		if got[ref(valDoHTemplates)] != sz(want.Template) {
			t.Errorf("%s: %s = %v, want %q", k, valDoHTemplates, got[ref(valDoHTemplates)], want.Template)
		}
	}
	// Microsoft's documentation is explicit that secure mode requires a non-empty
	// template, so the two must never be written apart. Written alone, the mode
	// would be a browser that resolves nothing at all.
	for _, k := range ChromiumKinds {
		got := wantedValues(k, false, h)
		_, mode := got[ref(valDoHMode)]
		_, tmpl := got[ref(valDoHTemplates)]
		if mode != tmpl {
			t.Errorf("%s: mode present=%v but template present=%v - secure mode with no template resolves nothing", k, mode, tmpl)
		}
	}

	for _, k := range GeckoKinds {
		got := wantedValues(k, true, h)
		if got[gref(valGeckoDoHEnabled)] != dword(1) {
			t.Errorf("%s: %s\\%s = %v, want 1", k, subGeckoDoH, valGeckoDoHEnabled, got[gref(valGeckoDoHEnabled)])
		}
		if got[gref(valGeckoDoHProvider)] != sz(want.Template) {
			t.Errorf("%s: %s\\%s = %v, want %q", k, subGeckoDoH, valGeckoDoHProvider, got[gref(valGeckoDoHProvider)], want.Template)
		}
		// Locked is what stops about:preferences pointing it somewhere else, and
		// Fallback 0 is the fail-closed half. Either one missing leaves a filter
		// that looks pinned and is not.
		if got[gref(valGeckoDoHLocked)] != dword(1) {
			t.Errorf("%s: %s\\%s = %v, want 1 - the user could repoint it", k, subGeckoDoH, valGeckoDoHLocked, got[gref(valGeckoDoHLocked)])
		}
		if got[gref(valGeckoDoHFallback)] != dword(0) {
			t.Errorf("%s: %s\\%s = %v, want 0 - it would fall back to the machine's resolver", k, subGeckoDoH, valGeckoDoHFallback, got[gref(valGeckoDoHFallback)])
		}
		if _, ok := got[ref(valDoHMode)]; ok {
			t.Errorf("%s: %s written, which is a Chromium policy", k, valDoHMode)
		}
	}

	// Unlike safe-search, this knob has no gap: every browser the guard writes
	// policy for gets it. A browser silently left out would be one whose DNS is
	// unfiltered while the window reports the setting as on.
	for _, k := range AllKinds() {
		if got := wantedValues(k, k.Gecko(), h); len(got) == 0 {
			t.Errorf("%s is asked for nothing by the DNS filter", k)
		}
	}
}

// TestEverythingWritableIsRemovable is the invariant that keeps an authorized
// uninstall - and the start of a pause - honest. RemoveHardening clears exactly
// the values in managedValues, so a value wantedValues can write that
// managedValues does not list would be left behind forever: Incognito would stay
// disabled after the guard was removed, or the browsers would keep resolving
// through a filter nobody could turn off, and the machine would not come back the
// way it was.
func TestEverythingWritableIsRemovable(t *testing.T) {
	// Every knob at once, and every resolver in turn: the template is part of the
	// value, so a resolver added to the table without being added to the managed
	// list would be unremovable.
	for _, r := range Resolvers {
		every := Hardening{PrivateBrowsing: true, SafeSearch: SafeSearchStrict, DNSFilter: r.ID}
		for _, k := range AllKinds() {
			managed := managedValues(k, k.Gecko())
			for at, val := range wantedValues(k, k.Gecko(), every) {
				ours, ok := managed[at]
				if !ok {
					t.Errorf("%s: %v can be written but is not managed, so it would never be cleared", k, at)
					continue
				}
				found := false
				for _, o := range ours {
					if o == val {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s: %v can be written as %v, which is not in its managed values %v - removal would leave it", k, at, val, ours)
				}
			}
		}
	}
}

// TestWantedValuesEmptyWhenNothingAsked holds that a config which hardens nothing
// asks nothing of any browser. syncPolicyValues creates no key when there is
// nothing to write and nothing of ours to remove, so this is what keeps an install
// that never turned any of this on completely untouched - including, now, the
// DNSOverHTTPS subkey, which must not appear on a machine with the filter off.
func TestWantedValuesEmptyWhenNothingAsked(t *testing.T) {
	for _, k := range AllKinds() {
		if got := wantedValues(k, k.Gecko(), Hardening{}); len(got) != 0 {
			t.Errorf("%s: wrote %v with no knob on", k, got)
		}
	}
}

// TestVerifyHardeningNotAvailable covers the branch that separates "nobody asked"
// from "somebody asked and this browser cannot do it". Reporting the second as
// "not configured" would hide a setting the user believes is enforced everywhere.
func TestVerifyHardeningNotAvailable(t *testing.T) {
	s := verifyHardeningOne(Status{Kind: Firefox}, mozillaPolicyPrefix+"Firefox", nil, "", nil, true)
	if s.Locked {
		t.Error("a browser that cannot enforce the setting reported it as enforced")
	}
	if s.Detail != "not available in firefox" {
		t.Errorf("Detail = %q, want \"not available in firefox\"", s.Detail)
	}
	if s := verifyHardeningOne(Status{Kind: Firefox}, mozillaPolicyPrefix+"Firefox", nil, "", nil, false); s.Detail != "not configured" {
		t.Errorf("with nothing asked, Detail = %q, want \"not configured\"", s.Detail)
	}
}
