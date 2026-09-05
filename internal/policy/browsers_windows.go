//go:build windows

package policy

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Windows already keeps the list this needs, because the Default Apps screen has
// to show one: SOFTWARE\Clients\StartMenuInternet, a subkey per registered
// browser, each naming the executable to open a page with. Reading that is how
// the guard finds browsers it has no name for - which is the whole point, since
// the interesting case is the browser nobody thought to put in a catalog.
//
// It is not the same question as DetectBrowsers, and both are worth having.
// DetectBrowsers asks "is Chrome here", from a fixed list of four, to decide
// whether a policy the guard writes has anything to act on. This asks "what is
// here", from no list at all, to find the ones no policy covers.

// browserListRoots are every place a browser registration can appear, and all
// three are needed.
//
// HKLM is a machine-wide install. WOW6432Node is a 32-bit browser on 64-bit
// Windows, which is still how some Firefox forks ship. HKCU is a per-user
// install - and that one matters most here, because a per-user install needs no
// administrator: it is precisely the install a standard account can perform for
// itself, which makes it the likely shape of the bypass this code is looking for.
//
// The HKCU half is read as whoever is running, so it finds the calling user's
// per-user installs and not another account's. That is a real limit and it is why
// nothing in the service reads this: a service running as LocalSystem would be
// reading SYSTEM's own profile and would find nothing, the same session-0
// blindness that window-title rules have. The callers are the CLI and the status
// window, both of which run as the person whose machine it is.
var browserListRoots = []struct {
	root registry.Key
	path string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Clients\StartMenuInternet`},
	{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Clients\StartMenuInternet`},
	{registry.CURRENT_USER, `SOFTWARE\Clients\StartMenuInternet`},
}

// BrowserScanSupported reports whether this platform can enumerate the installed
// browsers. Callers use it to tell "checked, found nothing" apart from "could not
// check", because printing a clean bill of health for a scan that never ran is
// the kind of quiet reassurance this app has no business giving.
func BrowserScanSupported() bool { return true }

// scanBrowsers reads the machine. It is unexported because RegisteredBrowsers in
// browsers.go is the way in - going through there is what keeps the whole package
// testable against a described machine rather than this one.
//
// A registration that cannot be read at all is skipped rather than failing the
// scan: one malformed key left by a half-uninstalled browser must not hide the
// other five. A registration with no readable executable is still returned, with
// an empty Exe, because something registered itself as a browser and that is
// worth showing even when the guard cannot say where it lives.
func scanBrowsers() []InstalledBrowser {
	var out []InstalledBrowser
	// A browser commonly registers in more than one root (a per-machine install
	// that also writes HKCU, or a 32-bit one visible through both views), so the
	// executable is what identifies it, not the key it was found under.
	seen := make(map[string]bool)

	for _, r := range browserListRoots {
		names := subKeyNames(r.root, r.path)
		for _, name := range names {
			b, ok := readBrowserRegistration(r.root, r.path+`\`+name, name)
			if !ok {
				continue
			}
			key := strings.ToLower(normalizeWinPath(b.Exe))
			if key == "" {
				// Nothing to identify it by but the registration's own name, which
				// is at least stable across the three roots.
				key = "name:" + strings.ToLower(name)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, b)
		}
	}
	sortBrowsers(out)
	return out
}

// subKeyNames lists a key's children, returning nothing when the key is absent -
// which is the ordinary case for WOW6432Node on a machine with no 32-bit browser.
func subKeyNames(root registry.Key, path string) []string {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	return names
}

// readBrowserRegistration reads one registration into an InstalledBrowser.
//
// Classification happens here, in both of its forms, because this is the one
// place that has the full path: the executable name settles the browsers the
// guard knows, and for anything left over the install itself is asked what it is
// called. That second question is what covers a Firefox fork nobody listed - see
// gecko.go - and it is asked only of a registration whose file is actually
// there, since a name read from a missing install would be a browser invented
// out of a stale registry key.
func readBrowserRegistration(root registry.Key, path, keyName string) (InstalledBrowser, bool) {
	exe := exeFromCommand(stringValue(root, path+`\shell\open\command`, ""))
	name := browserDisplayName(root, path, keyName)
	if exe == "" && strings.TrimSpace(name) == "" {
		// Neither a name nor a command: not a registration, just a stray key.
		return InstalledBrowser{}, false
	}
	exePath := normalizeWinPath(exe)
	b := InstalledBrowser{
		Name:    name,
		Exe:     exePath,
		Kind:    ClassifyBrowser(exe),
		Missing: exePath != "" && fileMissing(exePath),
	}
	if b.Kind == "" && exePath != "" && !b.Missing {
		if app := installAppName(exePath); app != "" {
			if kind, ok := geckoKindFor(app); ok {
				b.Kind, b.App = kind, app
			}
		}
	} else if b.Kind != "" {
		// A built-in browser carries its declared name too, so the policy key is
		// spelled the way the browser spells it whichever path set the Kind.
		for _, g := range builtinGecko {
			if g.Kind == b.Kind {
				b.App = g.Name
			}
		}
	}
	return b, true
}

// fileMissing reports that a path definitely names nothing, which is a stricter
// claim than fileExists elsewhere in this package makes and deliberately so.
//
// fileExists treats every error as absence, which is right for deciding whether a
// rule has anything to act on. Here the answer feeds a warning that something may
// have been renamed to evade a block, so only "not found" counts: a path we cannot
// stat because of a permission or a device error is not evidence of anything, and
// reporting it as a vanished file would be an accusation resting on a failed read.
func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

// browserDisplayName finds the friendliest name the registration offers.
//
// The key's own default value is preferred because it holds the plain display
// name ("Google Chrome", "Opera Stable"). Capabilities\ApplicationName is the
// documented place for it but is usually an indirect string - "@C:\...\app.exe,-108",
// a resource reference Windows expands and a plain registry read does not - so a
// value in that shape is passed over rather than shown as-is. The key's own name
// is the last resort: uglier for some browsers (Firefox registers under
// "Firefox-<hex>"), but always present and never a lie.
func browserDisplayName(root registry.Key, path, keyName string) string {
	if v := strings.TrimSpace(stringValue(root, path, "")); v != "" && !isIndirectString(v) {
		return v
	}
	if v := strings.TrimSpace(stringValue(root, path+`\Capabilities`, "ApplicationName")); v != "" && !isIndirectString(v) {
		return v
	}
	return strings.TrimSpace(keyName)
}

// isIndirectString reports whether a registry string is a resource reference
// rather than text to show. Windows writes these as "@<file>,-<id>".
func isIndirectString(s string) bool { return strings.HasPrefix(s, "@") }

// stringValue reads one string value, returning "" for anything unreadable. Every
// read here is best-effort by design: this is a report, and a key that will not
// open is a browser described less well, not a scan that fails.
func stringValue(root registry.Key, path, value string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, _, err := k.GetStringValue(value)
	if err != nil {
		return ""
	}
	return s
}
