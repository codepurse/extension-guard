//go:build !windows

package policy

// GeckoRunning lists the running Firefox-family browsers, which on Windows
// decides whether a domain change needs one of them restarted to be seen. Off
// Windows this says none: Chromium watches its managed-policy directory and
// picks changes up on its own, and the callers use this only to add a note, so a
// stub costs a note rather than a wrong block.
func GeckoRunning() []GeckoBrowser { return nil }
