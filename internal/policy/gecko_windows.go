//go:build windows

package policy

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The Windows half of gecko.go: where a policy key lives, and how a fork on this
// machine is turned into one.

// mozillaPolicyPrefix is the parent of every Firefox-family policy key. What
// follows it is the browser's own application name - see gecko.go.
const mozillaPolicyPrefix = `SOFTWARE\Policies\Mozilla\`

// builtinGecko are the Firefox-family browsers the guard knows without looking.
//
// They are listed rather than discovered for one reason: policy for a browser
// that is not installed yet is still worth writing, so the lock is already in
// place the day somebody installs it. Discovery cannot do that - it only sees
// what is there - so the browsers common enough to be worth pre-empting are
// named here, and the rest are found. Zen is in this list rather than left to
// discovery because it was checked directly, against its own copy of Mozilla's
// policy engine.
var builtinGecko = []GeckoBrowser{
	{Kind: Firefox, Name: "Firefox", Root: mozillaPolicyPrefix + "Firefox", Image: "firefox.exe"},
	{Kind: Zen, Name: "Zen", Root: mozillaPolicyPrefix + "Zen", Image: "zen.exe"},
}

// readInstallFile reads a file out of a browser's install directory. It is a var
// so a test can describe an install rather than needing one on the machine
// running the tests - the same seam, for the same reason, as browserScan.
var readInstallFile = os.ReadFile

// installAppName reads the application name a Gecko install declares next to its
// executable, or "" for an install that declares none.
//
// Both locations are tried because the file itself names both: application.ini
// sits beside the executable in every Firefox and Zen install checked, and its
// own header points at browser\application.ini as the copy an install can be
// started with. Reading the second as a fallback costs one failed open on a
// machine that does not have it.
func installAppName(exe string) string {
	dir := filepath.Dir(exe)
	for _, p := range []string{
		filepath.Join(dir, "application.ini"),
		filepath.Join(dir, "browser", "application.ini"),
	} {
		if data, err := readInstallFile(p); err == nil {
			if name := appNameFromINI(data); name != "" {
				return name
			}
		}
	}
	return ""
}

// The scan behind geckoBrowsers reads the registry and opens a file per
// registered browser, and it is asked for on every reconcile cycle, every status
// refresh and every knob-coverage line. Repeating it for each of those would be
// several scans a second on a machine where the answer changes when somebody
// installs a browser. So it is held for a few seconds - long enough to collapse
// one screenful of questions into one scan, short enough that a browser
// installed while the window is open shows up in it.
const geckoCacheTTL = 5 * time.Second

var (
	geckoMu     sync.Mutex
	geckoCached []GeckoBrowser
	geckoAt     time.Time
)

// geckoBrowsers is every Firefox-family browser to write policy for: the
// built-in ones, then every fork registered on this machine that said what it is
// called.
func geckoBrowsers() []GeckoBrowser {
	geckoMu.Lock()
	defer geckoMu.Unlock()
	if geckoCached != nil && time.Since(geckoAt) < geckoCacheTTL {
		return geckoCached
	}
	geckoCached, geckoAt = scanGeckoBrowsers(), time.Now()
	return geckoCached
}

// resetGeckoBrowsers drops the cached scan. Tests that describe a machine call it
// so the next question is answered by the machine they described rather than by
// the one the previous test did.
func resetGeckoBrowsers() {
	geckoMu.Lock()
	defer geckoMu.Unlock()
	geckoCached, geckoAt = nil, time.Time{}
}

// scanGeckoBrowsers does the work geckoBrowsers caches.
//
// The order is stable and deliberate - built-ins first, then discovered in scan
// order - because it decides the order of the rows in `guard verify` and in the
// status window, and a table that reshuffles itself between refreshes is one
// nobody can read.
//
// A fork whose Kind or policy root the guard already has is skipped rather than
// added twice. Tor Browser is why: it calls itself Firefox, so it resolves to the
// key that is already written, and adding it would produce two rows claiming the
// same key with different names.
func scanGeckoBrowsers() []GeckoBrowser {
	out := append([]GeckoBrowser(nil), builtinGecko...)
	seen := make(map[Kind]bool, len(out))
	for _, b := range out {
		seen[b.Kind] = true
	}
	for _, b := range browserScan() {
		if b.Kind == "" || seen[b.Kind] || b.Missing {
			continue
		}
		name := b.App
		if name == "" {
			continue
		}
		seen[b.Kind] = true
		out = append(out, GeckoBrowser{
			Kind:  b.Kind,
			Name:  name,
			Root:  mozillaPolicyPrefix + name,
			Image: b.Image(),
		})
	}
	return out
}

// policyTarget is one browser's policy root and which family it belongs to,
// which together are everything the hardening writer needs: where to write, and
// which browser's spelling of "no private windows" to write there.
type policyTarget struct {
	Kind  Kind
	Root  string
	Gecko bool
}

// policyTargets is every browser policy root on this machine, Chromium first so
// the order matches everything else the guard prints.
func policyTargets() []policyTarget {
	out := make([]policyTarget, 0, len(ChromiumKinds)+len(builtinGecko))
	for _, k := range ChromiumKinds {
		out = append(out, policyTarget{Kind: k, Root: chromiumPolicyRoot[k]})
	}
	for _, g := range geckoBrowsers() {
		out = append(out, policyTarget{Kind: g.Kind, Root: g.Root, Gecko: true})
	}
	return out
}
