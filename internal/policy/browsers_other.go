//go:build !windows

package policy

// Enumerating the installed browsers has no non-Windows implementation yet, and
// this returns nothing rather than a guess.
//
// The Linux equivalent exists - the .desktop files under /usr/share/applications
// and ~/.local/share/applications that declare x-scheme-handler/http - but it is
// a different piece of work, and the browsers category it would feed is
// Windows-shaped anyway: its rules name .exe files, and blocking an application
// at all is Windows-only here (see appblock_other.go).
//
// The important part is that this does not pretend. An empty list from a scan
// that ran means "no unmanaged browser on this machine"; an empty list from a
// scan that never ran means nothing at all. BrowserScanSupported is what lets the
// callers tell those apart and say "not checked on this platform" instead of
// printing a clean bill of health nobody earned.
func scanBrowsers() []InstalledBrowser { return nil }

// BrowserScanSupported reports whether this platform can enumerate the installed
// browsers. See RegisteredBrowsers.
func BrowserScanSupported() bool { return false }
