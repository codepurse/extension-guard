//go:build !windows

package policy

// GeckoRunning lists the running Firefox-family browsers, which on Windows
// decides whether a domain change needs one of them restarted to be seen. Off
// Windows this says none: Chromium watches its managed-policy directory and
// picks changes up on its own, and the callers use this only to add a note, so a
// stub costs a note rather than a wrong block.
func GeckoRunning() []GeckoBrowser { return nil }

// StaleGecko is the Windows-only companion to GeckoRunning: there it names the
// Firefox-family browsers still running the instance that was open when the
// policy last changed. Off Windows there is nothing to report, for the reason
// above - nothing goes stale that is not re-read on its own.
func StaleGecko() []GeckoBrowser { return nil }

// BrowsersRunning names every supported browser with a live process. Off Windows
// this says none, for the reason above: the managed-policy directory is watched,
// so nothing carries rules it can no longer be given. Its Windows twin exists
// because a Chromium browser there keeps an extension force-installed until it
// restarts, whatever the forcelist says by then.
func BrowsersRunning() []Kind { return nil }
