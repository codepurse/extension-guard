package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAllowlistOnOffAndCanonicalEncoding(t *testing.T) {
	base := Config{Domains: []Domain{{Name: "reddit.com"}}}
	want, err := base.Canonical()
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{Domains: []Domain{{Name: "reddit.com"}}}
	if !cfg.SetAllowlistOn(true) {
		t.Fatal("turning the mode on reported no change")
	}
	if cfg.SetAllowlistOn(true) {
		t.Error("turning it on twice reported a change")
	}
	if !cfg.AllowlistOn(at(20, 12, 0)) {
		t.Error("the mode is on but does not read as enforcing")
	}

	// Off with nothing else in it drops the object, so a config that used the mode
	// and stopped encodes byte-identically to one that never did. Every trusted copy
	// on disk depends on that.
	if !cfg.SetAllowlistOn(false) {
		t.Fatal("turning it off reported no change")
	}
	if cfg.Allowlist != nil {
		t.Error("the mode is off and empty but the object stayed")
	}
	got, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("canonical encoding after on+off:\n%s\nwant:\n%s", got, want)
	}
}

// A site list outlives the mode being switched off, exactly as a disabled domain
// stays on the block list. Having to rebuild it would make the mode unusable.
func TestAllowlistKeepsSitesWhenOff(t *testing.T) {
	var cfg Config
	if _, _, err := cfg.AddAllowed("wikipedia.org"); err != nil {
		t.Fatal(err)
	}
	cfg.SetAllowlistOn(true)
	cfg.SetAllowlistOn(false)
	if got := cfg.Allowing().AllowedSites(); len(got) != 1 || got[0] != "wikipedia.org" {
		t.Errorf("sites after switching off = %v", got)
	}
}

func TestAddAllowedNormalizesAndDeduplicates(t *testing.T) {
	var cfg Config
	host, changed, err := cfg.AddAllowed("https://WWW.Wikipedia.org/wiki/Go?x=1")
	if err != nil || !changed {
		t.Fatalf("AddAllowed: host=%q changed=%v err=%v", host, changed, err)
	}
	if host != "wikipedia.org" {
		t.Errorf("host = %q, want wikipedia.org", host)
	}
	if _, changed, err := cfg.AddAllowed("wikipedia.org"); err != nil || changed {
		t.Errorf("adding it again: changed=%v err=%v", changed, err)
	}
	if _, _, err := cfg.AddAllowed("*"); err == nil {
		t.Error("a bare asterisk was accepted onto the allowlist")
	}
}

// The contradiction guardrail. Chromium gives an allowlist entry precedence over a
// blocklist entry of the same specificity, so accepting both would make
// `guard domains` report a site as blocked while the browser let it through.
func TestAllowlistRefusesASiteTheBlockListCovers(t *testing.T) {
	cfg := Config{Domains: []Domain{{Name: "reddit.com"}}}
	_, changed, err := cfg.AddAllowed("old.reddit.com")
	if err == nil {
		t.Fatal("a site covered by the block list was allowed")
	}
	if changed {
		t.Error("the refusal still changed the config")
	}
	if !strings.Contains(err.Error(), "unblock") {
		t.Errorf("the error does not say how to resolve it: %v", err)
	}

	// And again at load, so a config that reached this shape by hand is refused
	// rather than enforcing a block the browser is going to override.
	bad := Config{
		Domains:   []Domain{{Name: "reddit.com"}},
		Allowlist: &Allowlist{On: true, Sites: []string{"reddit.com"}},
	}
	if err := bad.Validate(); err == nil {
		t.Error("a config with a site on both lists passed validation")
	}
}

func TestRemoveAllowed(t *testing.T) {
	var cfg Config
	cfg.AddAllowed("wikipedia.org")
	if host, removed := cfg.RemoveAllowed("WWW.Wikipedia.org"); !removed || host != "wikipedia.org" {
		t.Errorf("RemoveAllowed = (%q, %v)", host, removed)
	}
	if _, removed := cfg.RemoveAllowed("wikipedia.org"); removed {
		t.Error("removing it twice reported a removal")
	}
}

// The gate, which is the inverse of the block list's in both halves.
func TestAllowNarrows(t *testing.T) {
	for action, want := range map[string]bool{
		AllowActionOn:      false, // blocks the whole web
		AllowActionOff:     true,  // unblocks the whole web
		AllowActionAllow:   true,  // opens something the mode had closed
		AllowActionUnallow: false, // closes it again
	} {
		if got := AllowNarrows(action); got != want {
			t.Errorf("AllowNarrows(%q) = %v, want %v", action, got, want)
		}
	}
}

func TestAllowWindowNarrows(t *testing.T) {
	window := []Window{{Start: "09:00", End: "17:00"}}

	// Off: nothing is enforced, so a timetable changes nothing.
	off := Config{}
	if off.AllowWindowNarrows(window) {
		t.Error("setting a window on a mode that is off was called a weakening")
	}
	// On around the clock, then given hours: enforcement shrinks.
	always := Config{Allowlist: &Allowlist{On: true}}
	if !always.AllowWindowNarrows(window) {
		t.Error("going from always to a window was not called a weakening")
	}
	// Going back to around the clock only widens.
	windowed := Config{Allowlist: &Allowlist{On: true, Windows: window}}
	if windowed.AllowWindowNarrows(nil) {
		t.Error("dropping a window was called a weakening")
	}
}

// A window shuts the mode off for the moments outside it, and the signature has to
// move with it - otherwise crossing the boundary would wait for the 30s backstop
// instead of the 5s schedule check.
func TestAllowlistWindowResolvesAndMovesTheSignature(t *testing.T) {
	cfg := Config{Allowlist: &Allowlist{
		On:      true,
		Sites:   []string{"wikipedia.org"},
		Windows: []Window{{Days: []string{"mon"}, Start: "09:00", End: "17:00"}},
	}}
	inside, outside := at(17, 12, 0), at(17, 20, 0) // Monday noon, Monday evening

	if !cfg.AllowlistOn(inside) {
		t.Error("inside its window the mode does not read as enforcing")
	}
	if cfg.AllowlistOn(outside) {
		t.Error("outside its window the mode still reads as enforcing")
	}
	if !cfg.ActiveAt(inside).Allowing().On {
		t.Error("resolution switched the mode off inside its window")
	}
	if cfg.ActiveAt(outside).Allowing().On {
		t.Error("resolution left the mode on outside its window")
	}
	if cfg.ActiveSignature(inside) == cfg.ActiveSignature(outside) {
		t.Error("the signature does not change at the window boundary, so no re-apply would fire")
	}

	// Resolution must not write through the shared pointer: the receiver is the
	// caller's config, and mutating the pointee would switch their copy off too.
	_ = cfg.ActiveAt(outside)
	if !cfg.Allowlist.On {
		t.Error("resolving outside the window mutated the config it was called on")
	}
}

// A config with no blocks still has to resolve its allowlist - ActiveAtWith returns
// early in that case, and the allowlist is not governed by a block.
func TestAllowlistResolvesWithoutBlocks(t *testing.T) {
	cfg := Config{Allowlist: &Allowlist{On: true, Windows: []Window{{Days: []string{"tue"}, Start: "09:00", End: "17:00"}}}}
	if len(cfg.Blocks) != 0 {
		t.Fatal("fixture has blocks")
	}
	if cfg.ActiveAt(at(17, 12, 0)).Allowing().On { // Monday, so the Tuesday window is shut
		t.Error("a config with no blocks did not resolve its allowlist window")
	}
}

func TestValidateAllowlistWindows(t *testing.T) {
	bad := Config{Allowlist: &Allowlist{On: true, Windows: []Window{{Start: "09:00", End: "09:00"}}}}
	if err := bad.Validate(); err == nil {
		t.Error("a zero-length window passed validation")
	}
	bad.Allowlist.Windows = []Window{{Days: []string{"funday"}, Start: "09:00", End: "17:00"}}
	if err := bad.Validate(); err == nil {
		t.Error("an unknown day passed validation")
	}
	good := Config{Allowlist: &Allowlist{On: true, Windows: []Window{{Start: "22:00", End: "06:00"}}}}
	if err := good.Validate(); err != nil {
		t.Errorf("an overnight window was refused: %v", err)
	}
}

func TestAllowlistOnlyConfigLoads(t *testing.T) {
	var cfg Config
	if err := json.Unmarshal([]byte(`{"allowlist":{"on":true,"sites":["wikipedia.org"]}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Allowing().On {
		t.Fatal("the allowlist was dropped when it was the only field")
	}
	if len(cfg.Extensions) != 0 {
		t.Errorf("the legacy branch invented %d extensions", len(cfg.Extensions))
	}
}

func TestAllowlistScheduleSummary(t *testing.T) {
	if got := (Allowlist{}).ScheduleSummary(); got != "always" {
		t.Errorf("no windows = %q, want always", got)
	}
	a := Allowlist{Windows: []Window{{Days: []string{"mon"}, Start: "09:00", End: "17:00"}}}
	if got := a.ScheduleSummary(); !strings.Contains(got, "09:00") {
		t.Errorf("summary = %q", got)
	}
}
