//go:build !windows

package policy

// FirefoxRunning reports whether Firefox is running, which on Windows decides
// whether a domain change needs Firefox restarted to be seen. Off Windows this
// says no: Chromium watches its managed-policy directory and picks changes up on
// its own, and the callers use this only to add a note, so a stub costs a note
// rather than a wrong block.
func FirefoxRunning() bool { return false }
