//go:build windows

package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

// The fact Zen support rests on, written down where it can be argued with.
// Mozilla's policy engine does not read one shared key: it reads
// SOFTWARE\Policies\Mozilla\<application name>, and the application name is
// "Firefox" in Firefox and "Zen" in Zen. Writing Zen's policies into Firefox's
// key would leave Zen carrying none of the locked extensions and none of the
// blocked sites, while every row in the status window said it was covered - the
// exact half-truth `guard browsers` exists to stop.
func TestZenReadsItsOwnPolicyKeyRatherThanFirefoxs(t *testing.T) {
	roots := map[Kind]string{}
	for _, g := range builtinGecko {
		roots[g.Kind] = g.Root
	}
	if got, want := roots[Zen], `SOFTWARE\Policies\Mozilla\Zen`; got != want {
		t.Errorf("zen policy root = %q, want %q", got, want)
	}
	if roots[Zen] == roots[Firefox] {
		t.Error("zen and firefox share a policy root, so one of them is being written to the wrong key")
	}
}

// Every browser the guard writes policy for needs somewhere to write it, and a
// missing root is not a harmless no-op: an empty one turns
// "<root>\ExtensionSettings\<id>" into a key hanging off the top of HKLM. So a
// browser that reached this list without a root would not fail to enforce, it
// would write policy somewhere nothing reads and report it as enforced.
func TestEveryPolicyTargetHasItsOwnRootUnderPolicies(t *testing.T) {
	seen := map[string]Kind{}
	for _, target := range policyTargets() {
		root := strings.TrimSpace(target.Root)
		if root == "" {
			t.Errorf("%s: no policy root, so its policies would be written to the top of HKLM", target.Kind)
			continue
		}
		if !strings.HasPrefix(root, `SOFTWARE\Policies\`) {
			t.Errorf("%s: policy root %q is outside SOFTWARE\\Policies", target.Kind, root)
		}
		if other, dup := seen[strings.ToLower(root)]; dup {
			t.Errorf("%s and %s share the policy root %q", target.Kind, other, root)
		}
		seen[strings.ToLower(root)] = target.Kind
	}
}

// withInstalls describes what each install directory holds, so a test can have a
// browser on the machine without one being installed on the machine running the
// tests. Same seam, same reason, as withBrowsers.
func withInstalls(t *testing.T, files map[string]string) {
	t.Helper()
	prev := readInstallFile
	readInstallFile = func(path string) ([]byte, error) {
		if body, ok := files[strings.ToLower(filepath.Clean(path))]; ok {
			return []byte(body), nil
		}
		return nil, filepath.ErrBadPattern // any error: "this install does not have that file"
	}
	t.Cleanup(func() { readInstallFile = prev })
}

const libreWolfINI = "[App]\r\nVendor=LibreWolf\r\nName=LibreWolf\r\nVersion=145.0\r\n\r\n[Gecko]\r\nMinVersion=145.0\r\n"

// A fork ships its application.ini next to the executable, and its own header
// points at browser\application.ini as the other place an install can keep one.
// Both are read, because a fork that moved it is still a fork the guard can
// cover, and the cost of looking is one failed open.
func TestInstallAppNameReadsEitherLocation(t *testing.T) {
	withInstalls(t, map[string]string{
		`c:\progs\librewolf\application.ini`: libreWolfINI,
	})
	if got := installAppName(`C:\Progs\LibreWolf\librewolf.exe`); got != "LibreWolf" {
		t.Errorf("installAppName = %q, want LibreWolf", got)
	}

	withInstalls(t, map[string]string{
		`c:\progs\librewolf\browser\application.ini`: libreWolfINI,
	})
	if got := installAppName(`C:\Progs\LibreWolf\librewolf.exe`); got != "LibreWolf" {
		t.Errorf("installAppName from browser\\ = %q, want LibreWolf", got)
	}

	withInstalls(t, map[string]string{})
	if got := installAppName(`C:\Progs\Something\something.exe`); got != "" {
		t.Errorf("installAppName on an install with no ini = %q, want empty", got)
	}
}

// The payoff of discovery, and the only test that states it end to end: a
// Firefox fork nobody listed is written for, under the key it named itself,
// because it was found on the machine rather than in a table.
func TestADiscoveredForkGetsItsOwnPolicyKey(t *testing.T) {
	withBrowsers(t, InstalledBrowser{
		Name: "LibreWolf",
		Exe:  `C:\Progs\LibreWolf\librewolf.exe`,
		Kind: "librewolf",
		App:  "LibreWolf",
	})

	var found *GeckoBrowser
	for _, g := range geckoBrowsers() {
		if g.Kind == "librewolf" {
			b := g
			found = &b
		}
	}
	if found == nil {
		t.Fatal("a registered fork that said what it is called was not written for")
	}
	if want := `SOFTWARE\Policies\Mozilla\LibreWolf`; found.Root != want {
		t.Errorf("root = %q, want %q", found.Root, want)
	}
	if found.Image != "librewolf.exe" {
		t.Errorf("image = %q, want librewolf.exe - a running fork would not be recognized", found.Image)
	}

	// The row has to appear everywhere a browser appears, or the guard writes a
	// policy nothing reports on.
	var listed bool
	for _, k := range AllKinds() {
		listed = listed || k == "librewolf"
	}
	if !listed {
		t.Error("the fork is written for but has no row in AllKinds")
	}
	if !DetectBrowsers()["librewolf"] {
		t.Error("the fork reads as not installed, though it was found by reading its own install")
	}
	// It is a Firefox underneath, so it inherits both the policy that exists and
	// the one that does not.
	if !KnobSupported(KnobPrivateBrowsing, "librewolf") {
		t.Error("private browsing reported unsupported in a Firefox fork")
	}
	if KnobSupported(KnobSafeSearch, "librewolf") {
		t.Error("safe-search reported supported in a Firefox fork, which has no policy for it")
	}
}

// Tor Browser calls itself Firefox. It must not become a second row claiming
// Firefox's own key under another name, and a fork whose file is gone or which
// declares nothing must not become a row at all - a policy key named after a
// browser that is not there is a claim about nothing.
func TestDiscoveryDropsWhatItCannotHonestlyAdd(t *testing.T) {
	withBrowsers(t,
		InstalledBrowser{Name: "Tor Browser", Exe: `C:\Progs\Tor\firefox.exe`, Kind: Firefox, App: "Firefox"},
		InstalledBrowser{Name: "Waterfox", Exe: `C:\Progs\Waterfox\waterfox.exe`, Kind: "waterfox", App: "Waterfox", Missing: true},
		InstalledBrowser{Name: "Opera Stable", Exe: `C:\Progs\Opera\opera.exe`},
	)
	got := geckoBrowsers()
	if len(got) != len(builtinGecko) {
		t.Fatalf("geckoBrowsers = %+v, want only the built-in browsers", got)
	}
}
