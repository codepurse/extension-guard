package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeSafeSearch(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: ""},
		{in: "off", want: ""},
		{in: "OFF", want: ""},
		{in: " moderate ", want: SafeSearchModerate},
		{in: "strict", want: SafeSearchStrict},
		// "on" without a level resolves to the stronger reading, not the weaker one.
		{in: "on", want: SafeSearchStrict},
		{in: "sometimes", wantErr: true},
	} {
		got, err := NormalizeSafeSearch(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NormalizeSafeSearch(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeSafeSearch(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeSafeSearch(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHardenedReadsNilAsNothing(t *testing.T) {
	var cfg Config
	h := cfg.Hardened()
	if h.Any() {
		t.Fatal("a config with no hardening reports some")
	}
	if got := h.Describe(KnobPrivateBrowsing); got != "off" {
		t.Errorf("Describe = %q, want off", got)
	}
	// An unreadable level must not read as enforced: it is refused by Validate, and
	// until it is corrected the guard writes nothing for it.
	cfg.Hardening = &Hardening{SafeSearch: "sometimes"}
	if _, on := cfg.Hardened().SafeSearchOn(); on {
		t.Error("an invalid SafeSearch level reads as on")
	}
}

func TestSetKnob(t *testing.T) {
	var cfg Config

	changed, err := cfg.SetKnob(KnobPrivateBrowsing, true, "")
	if err != nil || !changed {
		t.Fatalf("turning private-browsing on: changed=%v err=%v", changed, err)
	}
	if !cfg.Hardened().PrivateBrowsing {
		t.Fatal("private-browsing did not take")
	}
	// Turning on what is already on changes nothing, so the caller can say so
	// instead of writing the config again.
	if changed, err := cfg.SetKnob(KnobPrivateBrowsing, true, ""); err != nil || changed {
		t.Errorf("re-enabling reported changed=%v err=%v", changed, err)
	}
	if _, err := cfg.SetKnob(KnobPrivateBrowsing, true, "strict"); err == nil {
		t.Error("private-browsing accepted a level")
	}

	if _, err := cfg.SetKnob(KnobSafeSearch, true, "moderate"); err != nil {
		t.Fatalf("safe-search moderate: %v", err)
	}
	if got := cfg.Hardened().Describe(KnobSafeSearch); got != SafeSearchModerate {
		t.Errorf("Describe(safe-search) = %q, want moderate", got)
	}
	// Changing the level is a change even though the knob was already on.
	if changed, err := cfg.SetKnob(KnobSafeSearch, true, "strict"); err != nil || !changed {
		t.Errorf("raising the level reported changed=%v err=%v", changed, err)
	}
	if _, err := cfg.SetKnob(KnobSafeSearch, false, "strict"); err == nil {
		t.Error("turning safe-search off accepted a level")
	}
	if _, err := cfg.SetKnob("nonsense", true, ""); err == nil {
		t.Error("an unknown knob was accepted")
	}
}

// TestSetKnobDropsEmptyHardening holds the encoding invariant the trusted copy
// depends on: a config that hardened something and then stopped has to encode
// byte-identically to one that never hardened anything, or Commit and the tamper
// check would see a difference where there is none.
func TestSetKnobDropsEmptyHardening(t *testing.T) {
	base := Config{Extensions: []Extension{{Name: "blocknsfw"}}}
	want, err := base.Canonical()
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{Extensions: []Extension{{Name: "blocknsfw"}}}
	if _, err := cfg.SetKnob(KnobPrivateBrowsing, true, ""); err != nil {
		t.Fatal(err)
	}
	if hardened, err := cfg.Canonical(); err != nil {
		t.Fatal(err)
	} else if string(hardened) == string(want) {
		t.Fatal("turning a knob on did not change the canonical encoding")
	}
	if _, err := cfg.SetKnob(KnobPrivateBrowsing, false, ""); err != nil {
		t.Fatal(err)
	}
	if cfg.Hardening != nil {
		t.Error("the last knob went off but the Hardening object stayed")
	}
	got, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("canonical encoding after on+off:\n%s\nwant:\n%s", got, want)
	}
}

// TestHardenWeakens holds the one inverted gate here. Turning a setting on is a
// strengthening and costs admin alone, but SafeSearch has two on-states, and
// asking for the weaker one on a machine set to the stronger is a request to
// filter less - which must cost the password, or it would be the only way to
// weaken protection without it.
func TestHardenWeakens(t *testing.T) {
	off := Config{}
	if off.HardenWeakens(KnobSafeSearch, SafeSearchModerate) {
		t.Error("turning safe-search on from off was called a weakening")
	}

	moderate := Config{Hardening: &Hardening{SafeSearch: SafeSearchModerate}}
	if moderate.HardenWeakens(KnobSafeSearch, SafeSearchStrict) {
		t.Error("raising moderate to strict was called a weakening")
	}
	if moderate.HardenWeakens(KnobSafeSearch, SafeSearchModerate) {
		t.Error("setting the level it already has was called a weakening")
	}

	strict := Config{Hardening: &Hardening{SafeSearch: SafeSearchStrict}}
	if !strict.HardenWeakens(KnobSafeSearch, SafeSearchModerate) {
		t.Error("lowering strict to moderate was not called a weakening")
	}
	// An omitted level means strict (NormalizeSafeSearch), so it cannot lower one.
	if strict.HardenWeakens(KnobSafeSearch, "") {
		t.Error("an omitted level was treated as a weakening")
	}
	// private-browsing is on or off; on is stronger, and off goes through unharden,
	// which takes the password already.
	if strict.HardenWeakens(KnobPrivateBrowsing, "") {
		t.Error("private-browsing reported a weakening it cannot have")
	}
}

func TestKnobSupportAndGaps(t *testing.T) {
	for _, k := range []Kind{Chrome, Edge, Brave, Firefox} {
		if !KnobSupported(KnobPrivateBrowsing, k) {
			t.Errorf("private-browsing reported unsupported in %s", k)
		}
	}
	if KnobSupported(KnobSafeSearch, Firefox) {
		t.Error("safe-search reported supported in Firefox, which has no policy for it")
	}

	// A knob that is off produces no gap - the note is about what is being enforced
	// and where it does not reach, not a list of everything Firefox cannot do.
	if gaps := (Hardening{PrivateBrowsing: true}).Gaps(); len(gaps) != 0 {
		t.Errorf("private-browsing alone produced gaps: %v", gaps)
	}
	gaps := (Hardening{SafeSearch: SafeSearchStrict}).Gaps()
	if len(gaps) != 1 || !strings.Contains(gaps[0], "firefox") {
		t.Errorf("Gaps() = %v, want one mentioning firefox", gaps)
	}
}

func TestPrivateBrowsingOpen(t *testing.T) {
	lockable := Extension{
		Name:   "blocknsfw",
		Chrome: Target{ExtensionID: "ekdegpeejlidlkofccgakfdbiegmicmj", UpdateURL: "https://example.invalid/crx"},
	}

	locked := Config{Extensions: []Extension{lockable}}
	if !locked.PrivateBrowsingOpen() {
		t.Error("an extension is locked and private browsing is available, but nothing is reported")
	}
	hardened := locked
	if _, err := hardened.SetKnob(KnobPrivateBrowsing, true, ""); err != nil {
		t.Fatal(err)
	}
	if hardened.PrivateBrowsingOpen() {
		t.Error("private browsing is pinned off but still reported as open")
	}

	// Nothing is being locked, so there is no hole to report. Warning in either of
	// these cases would put a permanent warning on a machine with no lock to
	// sidestep, which teaches the reader to ignore it on the day it matters.
	off := lockable
	off.Disabled = true
	if (Config{Extensions: []Extension{off}}).PrivateBrowsingOpen() {
		t.Error("the only extension is switched off but the hole was reported anyway")
	}
	placeholder := Config{Extensions: []Extension{{
		Name:   "sieve",
		Chrome: Target{ExtensionID: "REPLACE_WITH_SIEVE_CHROME_ID", UpdateURL: "https://example.invalid/crx"},
	}}}
	if placeholder.PrivateBrowsingOpen() {
		t.Error("an unfilled placeholder locks nothing, but the hole was reported")
	}
}

func TestValidateRejectsUnknownLevel(t *testing.T) {
	cfg := Config{Hardening: &Hardening{SafeSearch: "sometimes"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("an unknown SafeSearch level passed validation")
	}
	cfg.Hardening.SafeSearch = SafeSearchStrict
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a valid level was refused: %v", err)
	}
}

// TestConfigWithOnlyHardeningLoads covers the shape-detection branch in
// UnmarshalJSON: a config that pins browser settings and nothing else names no
// extension, domain or app, and falling through to the legacy single-extension
// branch would silently discard it.
func TestConfigWithOnlyHardeningLoads(t *testing.T) {
	var cfg Config
	if err := json.Unmarshal([]byte(`{"hardening":{"privateBrowsing":true}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Hardened().PrivateBrowsing {
		t.Fatal("hardening was dropped when it was the only field")
	}
	if len(cfg.Extensions) != 0 {
		t.Errorf("the legacy branch invented %d extensions", len(cfg.Extensions))
	}
}

func TestHardeningRoundTrip(t *testing.T) {
	cfg := Config{
		Extensions: []Extension{{Name: "blocknsfw"}},
		Hardening:  &Hardening{PrivateBrowsing: true, SafeSearch: SafeSearchModerate},
	}
	data, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	h := back.Hardened()
	if !h.PrivateBrowsing {
		t.Error("privateBrowsing did not survive the round trip")
	}
	if level, on := h.SafeSearchOn(); !on || level != SafeSearchModerate {
		t.Errorf("safeSearch survived as (%q, %v), want (moderate, true)", level, on)
	}
}

// TestHardeningSurvivesScheduleResolution holds that hardening is not schedulable:
// ActiveAtWith narrows extensions, domains and apps, and must leave the pinned
// browser settings exactly as configured. A knob that switched itself off when a
// block's window closed would be a knob that does nothing.
func TestHardeningSurvivesScheduleResolution(t *testing.T) {
	cfg := Config{
		Extensions: []Extension{{Name: "blocknsfw"}},
		Blocks:     []Block{{ID: "nights", Windows: []Window{{Start: "22:00", End: "06:00"}}}},
		Hardening:  &Hardening{PrivateBrowsing: true},
	}
	active := cfg.ActiveAtWith(at(17, 12, 0), Spent{})
	if !active.Hardened().PrivateBrowsing {
		t.Error("hardening was resolved away outside a block's window")
	}
}
