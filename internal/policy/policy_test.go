package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChromiumForcelistValue(t *testing.T) {
	got, err := chromiumForcelistValue(Target{ExtensionID: "abc123", UpdateURL: "https://u/crx"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "abc123;https://u/crx"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestChromiumForcelistValueRejectsPlaceholder(t *testing.T) {
	if _, err := chromiumForcelistValue(Target{ExtensionID: "REPLACE_WITH_ID", UpdateURL: "https://u/crx"}); err == nil {
		t.Fatal("expected error for placeholder extension id")
	}
}

func TestChromiumForcelistValueRejectsIncomplete(t *testing.T) {
	if _, err := chromiumForcelistValue(Target{ExtensionID: "abc123"}); err == nil {
		t.Fatal("expected error for missing update url")
	}
}

func TestFirefoxConfigured(t *testing.T) {
	cases := []struct {
		name string
		t    Target
		want bool
	}{
		{"complete", Target{AddonID: "a@b", InstallURL: "https://x.xpi"}, true},
		{"placeholder url", Target{AddonID: "a@b", InstallURL: "REPLACE_WITH_SIGNED_XPI_URL"}, false},
		{"missing url", Target{AddonID: "a@b"}, false},
		{"missing id", Target{InstallURL: "https://x.xpi"}, false},
	}
	for _, c := range cases {
		if got := firefoxConfigured(c.t); got != c.want {
			t.Errorf("%s: firefoxConfigured = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestChromiumForcelistValues(t *testing.T) {
	targets := []Target{
		{ExtensionID: "aaa", UpdateURL: "https://u/crx"},           // ok
		{ExtensionID: "REPLACE_WITH_ID", UpdateURL: "https://u/c"}, // placeholder -> skipped
		{ExtensionID: "bbb"},                             // incomplete -> skipped
		{ExtensionID: "ccc", UpdateURL: "https://u/crx"}, // ok
	}
	got := chromiumForcelistValues(targets)
	if len(got) != 2 || got[0] != "aaa;https://u/crx" || got[1] != "ccc;https://u/crx" {
		t.Fatalf("chromiumForcelistValues = %v, want [aaa..., ccc...]", got)
	}
}

func TestLoadConfigMultiExtension(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "extension-ids.json")
	content := `{
	  "extensions": [
	    { "name": "blocknsfw",
	      "chrome":  {"extensionId": "cid1", "updateUrl": "curl"},
	      "firefox": {"addonId": "fid1", "installUrl": "furl"} },
	    { "name": "sieve",
	      "chrome":  {"extensionId": "cid2", "updateUrl": "curl2"} }
	  ]
	}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Extensions) != 2 {
		t.Fatalf("got %d extensions, want 2", len(cfg.Extensions))
	}
	chromeTargets := cfg.Targets(Chrome)
	if len(chromeTargets) != 2 || chromeTargets[0].ExtensionID != "cid1" || chromeTargets[1].ExtensionID != "cid2" {
		t.Errorf("chrome targets = %+v, want cid1/cid2", chromeTargets)
	}
	if got := cfg.Extensions[0].Target(Firefox).InstallURL; got != "furl" {
		t.Errorf("firefox installUrl = %q, want %q", got, "furl")
	}
	// sieve has no firefox target
	if got := cfg.Extensions[1].Target(Firefox); got != (Target{}) {
		t.Errorf("sieve firefox target = %+v, want empty", got)
	}
}

func TestLoadConfigLegacyFlat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ids.json")
	// The pre-multi-extension flat shape must still load, wrapped as one extension.
	content := `{
	  "chrome":  {"extensionId": "cid", "updateUrl": "curl"},
	  "firefox": {"addonId": "fid", "installUrl": "furl"}
	}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Extensions) != 1 {
		t.Fatalf("got %d extensions, want 1 (legacy wrapped)", len(cfg.Extensions))
	}
	if got := cfg.Targets(Chrome); len(got) != 1 || got[0].ExtensionID != "cid" {
		t.Errorf("chrome targets = %+v, want [cid]", got)
	}
	if got := cfg.Targets(Firefox); len(got) != 1 || got[0].InstallURL != "furl" {
		t.Errorf("firefox targets = %+v, want [furl]", got)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func sampleCatalog() Config {
	return Config{Extensions: []Extension{
		{Name: "blocknsfw", Chrome: Target{ExtensionID: "b", UpdateURL: "https://u/crx"}},
		{Name: "sieve", Chrome: Target{ExtensionID: "s", UpdateURL: "https://u/crx"}},
	}}
}

func TestTargetsSkipsDisabled(t *testing.T) {
	c := sampleCatalog()
	if got := c.Targets(Chrome); len(got) != 2 {
		t.Fatalf("all enabled: got %d chrome targets, want 2", len(got))
	}
	if !c.SetEnabled("sieve", false) {
		t.Fatal("SetEnabled(sieve,false) returned false; name not found")
	}
	got := c.Targets(Chrome)
	if len(got) != 1 || got[0].ExtensionID != "b" {
		t.Fatalf("after disabling sieve: chrome targets = %+v, want just blocknsfw", got)
	}
	if !c.AnyEnabled() {
		t.Fatal("AnyEnabled should be true (blocknsfw still on)")
	}
}

func TestSetEnabledUnknown(t *testing.T) {
	c := sampleCatalog()
	if c.SetEnabled("nope", false) {
		t.Fatal("SetEnabled on an unknown name should return false")
	}
}

func TestEnableOnly(t *testing.T) {
	c := sampleCatalog()
	c.EnableOnly([]string{"sieve"})
	if !c.Extensions[0].Disabled {
		t.Error("blocknsfw should be disabled after EnableOnly(sieve)")
	}
	if c.Extensions[1].Disabled {
		t.Error("sieve should be enabled after EnableOnly(sieve)")
	}
	// empty list re-enables everything
	c.EnableOnly(nil)
	if c.Extensions[0].Disabled || c.Extensions[1].Disabled {
		t.Error("EnableOnly(nil) should enable all extensions")
	}
}

func TestOnly(t *testing.T) {
	c := sampleCatalog()
	c.SetEnabled("blocknsfw", false)
	only := c.Only("blocknsfw")
	if len(only.Extensions) != 1 || only.Extensions[0].Name != "blocknsfw" {
		t.Fatalf("Only(blocknsfw) = %+v, want just blocknsfw", only.Extensions)
	}
	if only.Extensions[0].Disabled {
		t.Error("Only() should force the returned extension enabled so its policy can be removed")
	}
}

// Zen takes its add-ons from addons.mozilla.org, the same store as Firefox, under
// the same add-on id and from the same install URL - so it force-installs the
// Firefox target rather than one of its own. That is what makes Zen support cost
// no change to any config that already exists, and if it ever stops being true
// this is the test to argue with first.
func TestZenForceInstallsTheSameAddOnAsFirefox(t *testing.T) {
	e := Extension{Firefox: Target{AddonID: "a@b", InstallURL: "https://x/x.xpi"}}
	if got, want := e.Target(Zen), e.Target(Firefox); got != want {
		t.Errorf("Target(Zen) = %+v, want the Firefox target %+v", got, want)
	}
	if !firefoxConfigured(e.Target(Zen)) {
		t.Error("Target(Zen) is not applyable, so nothing would be force-installed in Zen")
	}
	// A config that force-installs nothing in Firefox force-installs nothing in
	// Zen either, rather than falling back to a Chromium target it cannot use.
	chromiumOnly := Extension{Chrome: Target{ExtensionID: "abc", UpdateURL: "https://u/crx"}}
	if got := chromiumOnly.Target(Zen); got != (Target{}) {
		t.Errorf("Target(Zen) = %+v for a Chromium-only extension, want empty", got)
	}
}

// The restart caveat names browsers in prose, and the prose has to read right for
// one browser and for two - "Firefox applies this" against "Firefox and Zen apply
// this". Getting it wrong is not a crash, it is a sentence nobody trusts.
//
// It uses each browser's declared name rather than its Kind for the reason a
// discovered fork exists at all: the Kind is a lowercase identifier, and
// "librewolf applies this the next time it starts" is not a sentence anybody
// wrote on purpose.
func TestBrowserNamesReadsAsASentence(t *testing.T) {
	ff := GeckoBrowser{Kind: Firefox, Name: "Firefox"}
	zen := GeckoBrowser{Kind: Zen, Name: "Zen"}
	fork := GeckoBrowser{Kind: "librewolf", Name: "LibreWolf"}
	cases := []struct {
		in   []GeckoBrowser
		want string
	}{
		{nil, ""},
		{[]GeckoBrowser{ff}, "Firefox"},
		{[]GeckoBrowser{ff, zen}, "Firefox and Zen"},
		{[]GeckoBrowser{ff, zen, fork}, "Firefox, Zen and LibreWolf"},
	}
	for _, c := range cases {
		if got := BrowserNames(c.in); got != c.want {
			t.Errorf("BrowserNames(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// AllKinds is what the status table has a row for and what a hardening gap is
// measured against, so a browser missing from it is one the window never mentions
// and a browser in it twice is a row printed twice.
func TestAllKindsIsEveryBrowserOnceAndCannotBeReachedByACaller(t *testing.T) {
	seen := map[Kind]bool{}
	for _, k := range AllKinds() {
		if seen[k] {
			t.Errorf("%s appears twice in AllKinds", k)
		}
		seen[k] = true
	}
	for _, k := range ChromiumKinds {
		if !seen[k] {
			t.Errorf("%s is missing from AllKinds", k)
		}
	}
	if !seen[Firefox] {
		t.Error("firefox is missing from AllKinds")
	}
	// Appending to the returned slice must not reach ChromiumKinds' own backing
	// array, which is what the copy in AllKinds is for.
	_ = append(AllKinds(), "not-a-browser")
	if len(ChromiumKinds) != 3 || ChromiumKinds[0] != Chrome {
		t.Fatalf("ChromiumKinds was reachable through AllKinds: %v", ChromiumKinds)
	}
}
