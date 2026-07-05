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
