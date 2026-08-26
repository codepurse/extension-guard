//go:build windows

package policy

import "testing"

// TestWantedValuesPerBrowser pins the values each browser gets, because a wrong
// value here verifies perfectly and enforces nothing - the guard can only see that
// it wrote what it meant to write, never that the browser obeyed.
func TestWantedValuesPerBrowser(t *testing.T) {
	private := Hardening{PrivateBrowsing: true}

	for _, k := range ChromiumKinds {
		got := wantedValues(k, private)
		if got[valIncognito] != 1 {
			t.Errorf("%s: %s = %v, want 1", k, valIncognito, got[valIncognito])
		}
		// Guest mode is the bigger hole of the two: a guest session carries no
		// extensions at all, so it has to be named separately from Incognito.
		if v, ok := got[valGuestMode]; !ok || v != 0 {
			t.Errorf("%s: %s = %v (present %v), want 0", k, valGuestMode, v, ok)
		}
	}
	// Brave's private window has a second form the Chromium switch does not
	// describe.
	if _, ok := wantedValues(Brave, private)[valTorDisabled]; !ok {
		t.Errorf("brave: %s not written, so \"private window with Tor\" stays open", valTorDisabled)
	}
	if _, ok := wantedValues(Chrome, private)[valTorDisabled]; ok {
		t.Errorf("chrome: %s written, which is a Brave-only policy", valTorDisabled)
	}
	if got := wantedValues(Firefox, private); got[valFirefoxPrivate] != 1 {
		t.Errorf("firefox: %s = %v, want 1", valFirefoxPrivate, got[valFirefoxPrivate])
	}

	strict := Hardening{SafeSearch: SafeSearchStrict}
	moderate := Hardening{SafeSearch: SafeSearchModerate}
	for _, k := range ChromiumKinds {
		if got := wantedValues(k, strict); got[valGoogleSafe] != 1 || got[valYouTubeRestrict] != 2 {
			t.Errorf("%s strict: google=%v youtube=%v, want 1 and 2", k, got[valGoogleSafe], got[valYouTubeRestrict])
		}
		if got := wantedValues(k, moderate); got[valYouTubeRestrict] != 1 {
			t.Errorf("%s moderate: youtube=%v, want 1", k, got[valYouTubeRestrict])
		}
	}
	if _, ok := wantedValues(Edge, strict)[valBingSafe]; !ok {
		t.Errorf("edge: %s not written, so Bing is unfiltered in the browser that defaults to it", valBingSafe)
	}
	if _, ok := wantedValues(Chrome, strict)[valBingSafe]; ok {
		t.Errorf("chrome: %s written, which is an Edge-only policy", valBingSafe)
	}
	// Firefox has no SafeSearch policy, so it must be asked for nothing rather than
	// handed a value that does nothing. knobSupport is the single source for that,
	// and this is what holds the writer to it.
	if got := wantedValues(Firefox, strict); len(got) != 0 {
		t.Errorf("firefox safe-search wrote %v, want nothing", got)
	}
}

// TestEverythingWritableIsRemovable is the invariant that keeps an authorized
// uninstall - and the start of a pause - honest. RemoveHardening clears exactly
// the names in managedNames, so a value wantedValues can write that managedNames
// does not list would be left behind forever: Incognito would stay disabled after
// the guard was removed, and the machine would not come back the way it was.
func TestEverythingWritableIsRemovable(t *testing.T) {
	every := Hardening{PrivateBrowsing: true, SafeSearch: SafeSearchStrict}
	for _, k := range append(append([]Kind{}, ChromiumKinds...), Firefox) {
		managed := managedNames(k)
		for name, val := range wantedValues(k, every) {
			ours, ok := managed[name]
			if !ok {
				t.Errorf("%s: %s can be written but is not managed, so it would never be cleared", k, name)
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
				t.Errorf("%s: %s can be written as %d, which is not in its managed values %v - removal would leave it", k, name, val, ours)
			}
		}
	}
}

// TestWantedValuesEmptyWhenNothingAsked holds that a config which hardens nothing
// asks nothing of any browser. syncPolicyValues creates no key when there is
// nothing to write and nothing of ours to remove, so this is what keeps an install
// that never turned any of this on completely untouched.
func TestWantedValuesEmptyWhenNothingAsked(t *testing.T) {
	for _, k := range append(append([]Kind{}, ChromiumKinds...), Firefox) {
		if got := wantedValues(k, Hardening{}); len(got) != 0 {
			t.Errorf("%s: wrote %v with no knob on", k, got)
		}
	}
}

// TestVerifyHardeningNotAvailable covers the branch that separates "nobody asked"
// from "somebody asked and this browser cannot do it". Reporting the second as
// "not configured" would hide a setting the user believes is enforced everywhere.
func TestVerifyHardeningNotAvailable(t *testing.T) {
	s := verifyHardeningOne(Status{Kind: Firefox}, firefoxPolicyRoot, nil, true)
	if s.Locked {
		t.Error("a browser that cannot enforce the setting reported it as enforced")
	}
	if s.Detail != "not available in firefox" {
		t.Errorf("Detail = %q, want \"not available in firefox\"", s.Detail)
	}
	if s := verifyHardeningOne(Status{Kind: Firefox}, firefoxPolicyRoot, nil, false); s.Detail != "not configured" {
		t.Errorf("with nothing asked, Detail = %q, want \"not configured\"", s.Detail)
	}
}
