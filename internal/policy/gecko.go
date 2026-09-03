package policy

import (
	"strings"
)

// This file is how the guard covers a Firefox fork nobody has told it about.
//
// Mozilla's policy engine does not read one shared key. It reads
// SOFTWARE\Policies\Mozilla\<application name>, where the name is the browser's
// own: "Firefox" in Firefox, "Zen" in Zen, and whatever a fork calls itself in a
// fork. Everything else about the policies is identical - the same
// ExtensionSettings, the same WebsiteFilter, the same DisablePrivateBrowsing,
// the same add-on installed from the same URL on addons.mozilla.org - so the
// only thing standing between the guard and a fork is knowing that one word.
//
// The obvious way to get it is a list in the binary: Floorp, LibreWolf,
// Waterfox, and a new line every time somebody ships another one. This file does
// the opposite, and asks the browser. Every Gecko install ships an
// application.ini next to its executable with the name in it, so a fork that is
// on the machine can be read rather than guessed at, and a fork released next
// year is covered by code written today.
//
// Which matters because of what a guess costs here. A wrong policy key does not
// fail loudly: the write succeeds, verification passes - it verifies that the
// policy was *written*, which it was - and the browser reads a different key and
// carries none of it. The guard would report "filtered" over a browser enforcing
// nothing, which is worse than the browsers category naming it as one more
// browser to block. So the rule this file follows is that a browser is managed
// only when it has said what it is called:
//
//   - no application.ini, or no name in it -> not a Gecko browser as far as the
//     guard is concerned, and it stays in the unmanaged list where
//     `guard browsers` reports it as a hole to block.
//   - a name that is not a plain application name -> refused, see geckoKindFor.
//
// The limits, stated rather than discovered later. Discovery only finds a
// browser that is *installed*, so unlike the built-in browsers there is no
// policy written ahead of an install - a fork gets its key the first reconcile
// after it appears, not before. And the registration scan reads the calling
// user's HKCU (see browsers_windows.go), so the service, running as LocalSystem,
// sees machine-wide installs and not a per-user one; the window and the CLI,
// running as the person whose machine it is, see both and report the gap.

// GeckoBrowser is one Firefox-family browser the guard writes policy for: the
// built-in ones and every fork found on this machine.
type GeckoBrowser struct {
	// Kind is the identifier used in the config and the status table, which is
	// the declared name lowercased: firefox, zen, floorp.
	Kind Kind
	// Name is what the browser calls itself, in its own capitalization
	// ("LibreWolf"). It is both the last element of the policy key and the word
	// to use in a sentence.
	Name string
	// Root is the policy location: on Windows the registry key under HKLM.
	Root string
	// Image is the executable's file name, which is how a running process is
	// recognized as this browser.
	Image string
}

// BrowserNames lists browsers the way a sentence does: "Firefox", or "Firefox
// and Zen". Empty for an empty list, so a caller can test it and say nothing.
// BrowserNameList is BrowserNames without the joining: the names on their own,
// for a caller that renders them itself rather than dropping them into a
// sentence.
func BrowserNameList(list []GeckoBrowser) []string {
	out := make([]string, 0, len(list))
	for _, b := range list {
		out = append(out, b.Name)
	}
	return out
}

func BrowserNames(list []GeckoBrowser) string {
	names := make([]string, 0, len(list))
	for _, b := range list {
		names = append(names, b.Name)
	}
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// geckoKinds is the Kind of every browser in a list, for the callers that only
// need to name them.
func geckoKinds(list []GeckoBrowser) []Kind {
	out := make([]Kind, 0, len(list))
	for _, b := range list {
		out = append(out, b.Kind)
	}
	return out
}

// appNameFromINI reads the application name out of an application.ini, and
// returns "" for a file that is not one.
//
// Two things have to be true before the name counts. It has to be under [App],
// which is where a Gecko install writes it, and the file has to carry a [Gecko]
// section as well - that is the part that says this is a Gecko application
// rather than any other program that happens to ship an ini file with a Name in
// it. Firefox and Zen both write exactly this shape, and both were read off a
// real install to check it.
//
// The header of the file says "This file is not used", which is true of the file
// as configuration and beside the point here: the values are generated from the
// same build that compiled the name into the binary, so it is a description of
// the install even where it is not read by it.
func appNameFromINI(data []byte) string {
	var (
		section string
		name    string
		gecko   bool
	)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "gecko" {
				gecko = true
			}
			continue
		}
		if section != "app" || name != "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "Name") {
			continue
		}
		name = strings.TrimSpace(val)
	}
	if !gecko {
		return ""
	}
	return name
}

// maxAppNameLen caps a declared name at a length no real browser exceeds. It is
// not a formatting preference: the name becomes part of a registry key the guard
// creates under HKLM, and a file on disk decides it.
const maxAppNameLen = 40

// geckoKindFor turns a declared application name into the Kind the rest of the
// guard uses, or refuses it.
//
// The refusals are the point. This name arrives from a file inside a browser's
// own directory - which, for a per-user install, is a directory the user being
// filtered can write - and it is about to be pasted onto the end of a registry
// path under HKLM\SOFTWARE\Policies. So anything that is not a plain application
// name is rejected rather than sanitized: a separator would have the guard
// create keys somewhere it did not intend, and a name that is empty or absurdly
// long is not a browser identifying itself. A refused name means the browser
// stays unmanaged and keeps being reported as a hole, which is the safe
// direction - the dangerous one is inventing coverage.
//
// Names that collide with a browser the guard already handles are not refused
// here but dropped by the caller, which knows what it already has. Tor Browser
// is the case that matters: it calls itself "Firefox", and the Firefox key is
// already written.
func geckoKindFor(name string) (Kind, bool) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxAppNameLen {
		return "", false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == ' ', r == '.', r == '-', r == '_':
		default:
			return "", false
		}
	}
	kind := Kind(strings.ReplaceAll(strings.ToLower(name), " ", "-"))
	return kind, true
}
