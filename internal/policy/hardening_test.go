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
	for _, k := range []Kind{Chrome, Edge, Brave, Firefox, Zen} {
		if !KnobSupported(KnobPrivateBrowsing, k) {
			t.Errorf("private-browsing reported unsupported in %s", k)
		}
	}
	// A fork inherits the gap it forked from: neither has a SafeSearch policy, and
	// claiming one for Zen because it is newer would show a row as enforced that
	// nothing enforces.
	for _, k := range GeckoKinds {
		if KnobSupported(KnobSafeSearch, k) {
			t.Errorf("safe-search reported supported in %s, which has no policy for it", k)
		}
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

// TestNormalizeDNSFilter holds the resolver id to the same rule as a SafeSearch
// level: what the guard does not recognize is refused rather than quietly read as
// off. More is riding on it here - a config naming a resolver while the browsers
// resolve through whatever they used before is a machine whose DNS nobody is
// filtering and whose config says otherwise.
func TestNormalizeDNSFilter(t *testing.T) {
	for _, in := range []string{"", "off", "OFF", "  "} {
		if got, err := NormalizeDNSFilter(in); err != nil || got != "" {
			t.Errorf("NormalizeDNSFilter(%q) = %q, %v; want \"\", nil", in, got, err)
		}
	}
	// The friendly spellings all land on the one resolver there is. They have to
	// keep landing there when a second is added, or an upgrade would repoint a
	// machine's DNS at a different operator without anybody asking for it.
	for _, in := range []string{"on", "true", "yes", "cloudflare", "family", ResolverCloudflareFamily, "CLOUDFLARE-FAMILY"} {
		if got, err := NormalizeDNSFilter(in); err != nil || got != ResolverCloudflareFamily {
			t.Errorf("NormalizeDNSFilter(%q) = %q, %v; want %q", in, got, err, ResolverCloudflareFamily)
		}
	}
	for _, in := range []string{"quad9", "https://example.com/dns-query", "nonsense"} {
		if _, err := NormalizeDNSFilter(in); err == nil {
			t.Errorf("NormalizeDNSFilter(%q) was accepted; an unvetted resolver must not be", in)
		}
	}
}

// TestEveryResolverIsUsable checks the table rather than one entry: a resolver
// whose id does not normalize, or whose template is not an https URL, would be
// selectable and then written into every browser's DNS policy.
func TestEveryResolverIsUsable(t *testing.T) {
	if len(Resolvers) == 0 {
		t.Fatal("no resolver ships, so the knob can never be turned on")
	}
	seen := map[string]bool{}
	for _, r := range Resolvers {
		if got, err := NormalizeDNSFilter(r.ID); err != nil || got != r.ID {
			t.Errorf("resolver %q does not normalize to itself: %q, %v", r.ID, got, err)
		}
		if _, ok := LookupResolver(r.ID); !ok {
			t.Errorf("resolver %q is not findable by its own id", r.ID)
		}
		if seen[r.ID] {
			t.Errorf("resolver %q is listed twice", r.ID)
		}
		seen[r.ID] = true
		if !strings.HasPrefix(r.Template, "https://") {
			t.Errorf("resolver %q has template %q, which is not an https DoH endpoint", r.ID, r.Template)
		}
		for _, field := range []struct{ name, val string }{
			{"Label", r.Label}, {"Short", r.Short}, {"Covers", r.Covers},
		} {
			if strings.TrimSpace(field.val) == "" {
				t.Errorf("resolver %q has no %s, so the window would offer a blank row", r.ID, field.name)
			}
		}
		// Short lands in a ten-wide column in `guard hardening` and reads as the
		// state of the setting. Longer than that and the table stops lining up.
		if len(r.Short) > 10 {
			t.Errorf("resolver %q has Short %q (%d chars), which overflows the state column", r.ID, r.Short, len(r.Short))
		}
	}
}

// TestSetKnobDNSFilter walks the knob through the states the CLI and the window
// put it in.
func TestSetKnobDNSFilter(t *testing.T) {
	var cfg Config

	changed, err := cfg.SetKnob(KnobDNSFilter, true, "")
	if err != nil || !changed {
		t.Fatalf("turning dns-filter on: changed=%v err=%v", changed, err)
	}
	// An empty level means the default resolver rather than an error: `guard harden
	// dns-filter` with no flags is the way almost everybody will turn this on.
	r, on := cfg.Hardened().DNSFilterOn()
	if !on || r.ID != ResolverCloudflareFamily {
		t.Fatalf("DNSFilterOn() = %+v, %v; want the default resolver", r, on)
	}
	if !cfg.Hardened().On(KnobDNSFilter) || !cfg.Hardened().Any() {
		t.Error("the knob is on but On/Any do not say so")
	}
	// The state names who is filtering, not just that something is. With one
	// resolver that is guessable; with two it is the whole substance of the row.
	if got := cfg.Hardened().Describe(KnobDNSFilter); got != r.Short {
		t.Errorf("Describe(dns-filter) = %q, want %q", got, r.Short)
	}
	if changed, err := cfg.SetKnob(KnobDNSFilter, true, ""); err != nil || changed {
		t.Errorf("re-enabling reported changed=%v err=%v", changed, err)
	}
	if _, err := cfg.SetKnob(KnobDNSFilter, true, "quad9"); err == nil {
		t.Error("an unknown resolver was accepted")
	}
	if _, err := cfg.SetKnob(KnobDNSFilter, false, ResolverCloudflareFamily); err == nil {
		t.Error("turning dns-filter off accepted a resolver")
	}
	if _, err := cfg.SetKnob(KnobDNSFilter, false, ""); err != nil {
		t.Fatalf("turning dns-filter off: %v", err)
	}
	if cfg.Hardening != nil {
		t.Error("the last knob went off but the Hardening object stayed")
	}
}

// TestDNSFilterHasNoGap is the claim the knob's own note makes: unlike
// safe-search, every browser the guard writes policy for can be pinned. If a
// browser ever cannot, this fails and the note has to change with it - a row
// reading "on" over a browser resolving through its own DNS is the half-truth
// Gaps() exists to prevent.
func TestDNSFilterHasNoGap(t *testing.T) {
	h := Hardening{DNSFilter: ResolverCloudflareFamily}
	for _, k := range AllKinds() {
		if !KnobSupported(KnobDNSFilter, k) {
			t.Errorf("dns-filter is not supported in %s", k)
		}
	}
	if gaps := h.Gaps(); len(gaps) != 0 {
		t.Errorf("Gaps() = %v, want none", gaps)
	}
}

// TestValidateRejectsUnknownResolver mirrors TestValidateRejectsUnknownLevel: a
// hand-edited config naming a resolver the guard does not know is refused at load
// rather than enforcing nothing while claiming to filter.
func TestValidateRejectsUnknownResolver(t *testing.T) {
	cfg := Config{
		Extensions: []Extension{{Name: "blocknsfw"}},
		Hardening:  &Hardening{DNSFilter: "some-resolver"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("a config naming an unknown resolver validated")
	}
	// And it reads as off in the meantime, so nothing downstream acts on it.
	if _, on := cfg.Hardened().DNSFilterOn(); on {
		t.Error("an unknown resolver read as on")
	}
}

// TestPrivateExtensionsKnob covers the wiring a knob needs to exist at all: off
// until somebody says otherwise, its own state word rather than a bare "on", no
// level, and the encoding invariant TestSetKnobDropsEmptyHardening holds for the
// others - a config that turned this on and off again has to encode
// byte-identically to one that never touched it.
func TestPrivateExtensionsKnob(t *testing.T) {
	base := Config{Extensions: []Extension{{Name: "blocknsfw"}}}
	want, err := base.Canonical()
	if err != nil {
		t.Fatal(err)
	}

	cfg := base
	if cfg.Hardened().On(KnobPrivateExtensions) {
		t.Error("a config that asked for nothing reports the setting as on")
	}
	if _, err := cfg.SetKnob(KnobPrivateExtensions, true, ""); err != nil {
		t.Fatal(err)
	}
	h := cfg.Hardened()
	if !h.PrivateExtensions || !h.On(KnobPrivateExtensions) || !h.Any() {
		t.Errorf("after turning it on: %+v", h)
	}
	if got := h.Describe(KnobPrivateExtensions); got != "required" {
		t.Errorf("Describe = %q, want \"required\" - which of the two private-window "+
			"settings is in force is the part a reader cannot guess", got)
	}
	if _, err := cfg.SetKnob(KnobPrivateExtensions, true, "strict"); err == nil {
		t.Error("a level was accepted for a setting that has only on and off")
	}

	if _, err := cfg.SetKnob(KnobPrivateExtensions, false, ""); err != nil {
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

// TestMandatoryPrivateIDsIsEdgeOnly is the test that stops the worst version of
// this feature: a policy written for a browser that does not implement it, which
// would verify perfectly and enforce nothing. Chrome and Brave are the ones to
// watch - Chromium declares the equivalent policy for ChromeOS and not for
// desktop - and the Firefox family needs nothing, because the add-on is
// force-enabled in its private windows by the extension enforcer.
func TestMandatoryPrivateIDsIsEdgeOnly(t *testing.T) {
	const edgeID = "hkgfoiooedgoejojocmhlaklaeopbecg"
	cfg := Config{Extensions: []Extension{{
		Name:    "blocknsfw",
		Chrome:  Target{ExtensionID: "ekdegpeejlidlkofccgakfdbiegmicmj", UpdateURL: "https://example.invalid/crx"},
		Edge:    Target{ExtensionID: edgeID, UpdateURL: "https://example.invalid/crx"},
		Brave:   Target{ExtensionID: "ekdegpeejlidlkofccgakfdbiegmicmj", UpdateURL: "https://example.invalid/crx"},
		Firefox: Target{AddonID: "blocknsfw@example.invalid", InstallURL: "https://example.invalid/x.xpi"},
	}}}

	got := mandatoryPrivateIDs(cfg, Edge)
	if len(got) != 1 || got[0] != edgeID {
		t.Errorf("edge = %v, want [%s]", got, edgeID)
	}
	for _, k := range []Kind{Chrome, Brave, Firefox, Zen} {
		if ids := mandatoryPrivateIDs(cfg, k); len(ids) != 0 {
			t.Errorf("%s: would be written %v for a policy it does not implement", k, ids)
		}
	}
}

// TestMandatoryPrivateIDsSkipsPlaceholders holds the sharpest edge of this
// setting. Edge blocks InPrivate navigation when a *required* extension is not
// installed, so requiring an id nothing installs does not weaken protection - it
// leaves an InPrivate window that can never work no matter what the user allows,
// on a config whose author only forgot to fill in a placeholder.
func TestMandatoryPrivateIDsSkipsPlaceholders(t *testing.T) {
	cfg := Config{Extensions: []Extension{{
		Name: "sieve",
		Edge: Target{ExtensionID: "REPLACE_WITH_SIEVE_EDGE_ID", UpdateURL: "https://example.invalid/crx"},
	}}}
	if ids := mandatoryPrivateIDs(cfg, Edge); len(ids) != 0 {
		t.Errorf("an unfilled placeholder was required in InPrivate: %v", ids)
	}
}

// TestPrivateBrowsingOpenIsAskedPerBrowser holds the other half of the change.
// The warning used to be one question because the answer was the same in every
// browser; it is not any more, and a warning that fires on a machine with no hole
// is the warning nobody reads on the day it means something.
func TestPrivateBrowsingOpenIsAskedPerBrowser(t *testing.T) {
	geckoOnly := Config{Extensions: []Extension{{
		Name:    "blocknsfw",
		Firefox: Target{AddonID: "blocknsfw@example.invalid", InstallURL: "https://example.invalid/x.xpi"},
	}}}
	if geckoOnly.PrivateBrowsingOpen() {
		t.Error("a Firefox-only lock reported a hole; the add-on runs in its private windows")
	}

	edgeOnly := Config{Extensions: []Extension{{
		Name: "blocknsfw",
		Edge: Target{ExtensionID: "hkgfoiooedgoejojocmhlaklaeopbecg", UpdateURL: "https://example.invalid/crx"},
	}}}
	if !edgeOnly.PrivateBrowsingOpen() {
		t.Error("InPrivate is open and nothing requires the extension in it, but nothing is reported")
	}
	required := edgeOnly
	if _, err := required.SetKnob(KnobPrivateExtensions, true, ""); err != nil {
		t.Fatal(err)
	}
	if required.PrivateBrowsingOpen() {
		t.Error("InPrivate will not navigate without the extension, but the hole is still reported")
	}

	// The same setting on a machine that also locks Chrome closes nothing there,
	// so the warning has to stay up.
	withChrome := edgeOnly
	withChrome.Extensions = []Extension{{
		Name:   "blocknsfw",
		Chrome: Target{ExtensionID: "ekdegpeejlidlkofccgakfdbiegmicmj", UpdateURL: "https://example.invalid/crx"},
		Edge:   Target{ExtensionID: "hkgfoiooedgoejojocmhlaklaeopbecg", UpdateURL: "https://example.invalid/crx"},
	}}
	if _, err := withChrome.SetKnob(KnobPrivateExtensions, true, ""); err != nil {
		t.Fatal(err)
	}
	if !withChrome.PrivateBrowsingOpen() {
		t.Error("Chrome has no policy for requiring an extension in Incognito, but the hole was " +
			"reported closed")
	}
}

// TestPrivateExtensionsGapNamesItsOwnReason guards the sentence a reader acts on.
// The default - "there is no policy for it" - is true of Chrome and Brave here
// and false of Firefox and Zen, which need no policy, and sending somebody to
// look for a Firefox hole that does not exist is the failure this whole file is
// about.
func TestPrivateExtensionsGapNamesItsOwnReason(t *testing.T) {
	gaps := (Hardening{PrivateExtensions: true}).Gaps()
	if len(gaps) != 1 {
		t.Fatalf("Gaps() = %v, want one", gaps)
	}
	for _, browser := range []string{"chrome", "brave", "firefox", "zen"} {
		if !strings.Contains(gaps[0], browser) {
			t.Errorf("gap does not name %s: %q", browser, gaps[0])
		}
	}
	if strings.Contains(gaps[0], "there is no policy for it") {
		t.Errorf("gap gives the default reason, which is wrong for firefox and zen: %q", gaps[0])
	}
}
