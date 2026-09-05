package policy

import (
	"strings"
	"testing"
)

// chromeStore and edgeStore are the two update URLs a real catalog entry carries,
// spelled out here so a target in these tests is complete for the same reason a
// shipped one is - catalogSays rejects a half-filled target, and a test that
// omitted the URL would be exercising the rejection rather than the adoption.
const (
	chromeStore = "https://clients2.google.com/service/update2/crx"
	edgeStore   = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
)

func catalogOf(exts ...Extension) StoreCatalog { return StoreCatalog{Extensions: exts} }

// This is the bug the whole file exists for, reduced to its smallest form: a
// machine whose config predates an extension being published in some store has
// an empty target for it, and nothing but adoption can fill it in. Until it did,
// the browser reported "no id for this browser" for ever while the status window
// went on calling the extension protected.
func TestAdoptCatalogFillsABrowserThatHadNoID(t *testing.T) {
	cfg := Config{Extensions: []Extension{{
		Name:   "blocknsfw",
		Chrome: Target{ExtensionID: "chromeid", UpdateURL: chromeStore},
	}}}
	cat := catalogOf(Extension{
		Name:   "blocknsfw",
		Chrome: Target{ExtensionID: "chromeid", UpdateURL: chromeStore},
		Edge:   Target{ExtensionID: "edgeid", UpdateURL: edgeStore},
	})

	got, changes := cfg.AdoptCatalog(cat)
	if got.Extensions[0].Edge.ExtensionID != "edgeid" {
		t.Fatalf("Edge target = %+v, want the catalog's edgeid", got.Extensions[0].Edge)
	}
	if len(changes) != 1 {
		t.Fatalf("changes = %v, want exactly one line about Edge", changes)
	}
	if !strings.Contains(changes[0], "this browser had none") {
		t.Errorf("change line = %q, want it to say the browser had no id", changes[0])
	}
}

func TestAdoptCatalogCorrectsAPlaceholderLeftInTheConfig(t *testing.T) {
	cfg := Config{Extensions: []Extension{{
		Name: "sieve",
		Edge: Target{ExtensionID: "REPLACE_WITH_SIEVE_EDGE_ID", UpdateURL: edgeStore},
	}}}
	cat := catalogOf(Extension{
		Name: "sieve",
		Edge: Target{ExtensionID: "realedgeid", UpdateURL: edgeStore},
	})

	got, changes := cfg.AdoptCatalog(cat)
	if got.Extensions[0].Edge.ExtensionID != "realedgeid" {
		t.Fatalf("Edge id = %q, want realedgeid", got.Extensions[0].Edge.ExtensionID)
	}
	if len(changes) != 1 || !strings.Contains(changes[0], "placeholder") {
		t.Errorf("changes = %v, want one line naming the placeholder", changes)
	}
}

// The other direction, and the one that is easy to get wrong: a catalog with no
// opinion about a browser must not be read as an instruction to blank the
// machine's value. An extension with no listing in some store ships with an
// empty target, and a machine that acquired an id anyway keeps it.
func TestAdoptCatalogWillNotBlankABrowserTheCatalogSaysNothingAbout(t *testing.T) {
	cfg := Config{Extensions: []Extension{{
		Name: "sieve",
		Edge: Target{ExtensionID: "anidsomebodyhas", UpdateURL: edgeStore},
	}}}
	for _, cat := range []StoreCatalog{
		catalogOf(Extension{Name: "sieve"}),
		catalogOf(Extension{Name: "sieve", Edge: Target{ExtensionID: "REPLACE_ME", UpdateURL: edgeStore}}),
		catalogOf(Extension{Name: "sieve", Edge: Target{ExtensionID: "halffilled"}}),
	} {
		got, changes := cfg.AdoptCatalog(cat)
		if got.Extensions[0].Edge.ExtensionID != "anidsomebodyhas" {
			t.Errorf("Edge id = %q, want the machine's own id kept", got.Extensions[0].Edge.ExtensionID)
		}
		if len(changes) != 0 {
			t.Errorf("changes = %v, want none", changes)
		}
	}
}

// Adoption corrects where enforcement points and nothing else. Somebody who
// turned an extension off chose that, and an id correction is not a licence to
// revisit it - which is also what lets the callers run this without a password.
func TestAdoptCatalogNeverRevisitsADisabledFlag(t *testing.T) {
	cfg := Config{Extensions: []Extension{{
		Name:     "blocknsfw",
		Disabled: true,
	}}}
	cat := catalogOf(Extension{
		Name:   "blocknsfw",
		Chrome: Target{ExtensionID: "chromeid", UpdateURL: chromeStore},
	})

	got, _ := cfg.AdoptCatalog(cat)
	if !got.Extensions[0].Disabled {
		t.Fatal("adoption turned a switched-off extension back on")
	}
	if got.Extensions[0].Chrome.ExtensionID != "chromeid" {
		t.Error("the id should still be corrected on an extension that is switched off")
	}
}

// Everything in the config that is not a store id belongs to the machine. An
// adoption that dropped any of it would be a developer overwriting somebody's
// own decisions on the way past.
func TestAdoptCatalogCarriesTheMachinesOwnRulesThrough(t *testing.T) {
	cfg := Config{
		Extensions:       []Extension{{Name: "blocknsfw"}},
		Hardening:        &Hardening{PrivateBrowsing: true},
		BlockUnsupported: true,
		AutoUpdate:       "off",
	}
	cat := catalogOf(Extension{
		Name:   "blocknsfw",
		Chrome: Target{ExtensionID: "chromeid", UpdateURL: chromeStore},
	})

	got, _ := cfg.AdoptCatalog(cat)
	if got.Hardening == nil || !got.Hardening.PrivateBrowsing {
		t.Errorf("Hardening = %+v, want the machine's own setting kept", got.Hardening)
	}
	if !got.BlockUnsupported {
		t.Error("BlockUnsupported was dropped")
	}
	if got.AutoUpdate != "off" {
		t.Errorf("AutoUpdate = %q, want off", got.AutoUpdate)
	}
}

// A widened catalog is how a later version offers a new extension. It arrives
// listed but switched off, because force-installing something nobody asked for
// would change what is blocked on a machine without anybody agreeing to it.
func TestAdoptCatalogAddsANewExtensionSwitchedOff(t *testing.T) {
	cfg := Config{Extensions: []Extension{{Name: "blocknsfw"}}}
	cat := catalogOf(
		Extension{Name: "blocknsfw"},
		Extension{Name: "newthing", Label: "New Thing", Chrome: Target{ExtensionID: "n", UpdateURL: chromeStore}},
	)

	got, changes := cfg.AdoptCatalog(cat)
	if len(got.Extensions) != 2 {
		t.Fatalf("got %d extensions, want 2", len(got.Extensions))
	}
	added := got.Extensions[1]
	if added.Name != "newthing" {
		t.Fatalf("second extension = %q, want newthing", added.Name)
	}
	if !added.Disabled {
		t.Error("a newly catalogued extension must arrive switched off")
	}
	if len(changes) != 1 || !strings.Contains(changes[0], "switched off") {
		t.Errorf("changes = %v, want one line saying it arrived off", changes)
	}
}

func TestAdoptCatalogLeavesAnExtensionItNeverHeardOf(t *testing.T) {
	cfg := Config{Extensions: []Extension{{
		Name:   "somebodys-own",
		Chrome: Target{ExtensionID: "theirs", UpdateURL: chromeStore},
	}}}

	got, changes := cfg.AdoptCatalog(catalogOf(Extension{Name: "blocknsfw"}))
	if got.Extensions[0].Chrome.ExtensionID != "theirs" {
		t.Errorf("Chrome id = %q, want it untouched", got.Extensions[0].Chrome.ExtensionID)
	}
	// blocknsfw is still appended - the catalog naming it is the offer - but the
	// entry that was already there is not touched.
	if len(changes) != 1 || !strings.Contains(changes[0], "blocknsfw") {
		t.Errorf("changes = %v, want only the added blocknsfw line", changes)
	}
}

// An adoption that reported a change every start would commit the config every
// start, and each commit rewrites the trusted copy the tamper check compares
// against. Agreement has to read as silence.
func TestAdoptCatalogReportsNothingWhenTheConfigAlreadyAgrees(t *testing.T) {
	e := Extension{
		Name:   "blocknsfw",
		Chrome: Target{ExtensionID: "chromeid", UpdateURL: chromeStore},
		Edge:   Target{ExtensionID: "edgeid", UpdateURL: edgeStore},
	}
	got, changes := Config{Extensions: []Extension{e}}.AdoptCatalog(catalogOf(e))
	if len(changes) != 0 {
		t.Fatalf("changes = %v, want none", changes)
	}
	if got.Extensions[0] != e {
		t.Errorf("extension = %+v, want unchanged %+v", got.Extensions[0], e)
	}
}

// The catalog is the one copy of these ids that travels with the code, so a
// placeholder shipped in it is a browser that silently filters nothing on every
// machine. This is narrow on purpose: an extension with no listing in a store
// should carry an empty target, which adoption already reads as "no opinion".
// A REPLACE_ marker means somebody meant to fill it in and did not.
func TestShippedCatalogShipsNoPlaceholders(t *testing.T) {
	cat, err := EmbeddedCatalog()
	if err != nil {
		t.Fatalf("EmbeddedCatalog: %v", err)
	}
	if len(cat.Extensions) == 0 {
		t.Fatal("the embedded catalog is empty")
	}
	for _, e := range cat.Extensions {
		for _, k := range catalogKinds {
			tg := e.Target(k)
			for _, v := range []string{tg.ExtensionID, tg.UpdateURL, tg.AddonID, tg.InstallURL} {
				if isPlaceholder(v) {
					t.Errorf("%s/%s still ships a placeholder (%q)", e.Name, k, v)
				}
			}
		}
	}
}
