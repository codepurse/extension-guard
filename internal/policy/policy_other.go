//go:build !windows && !linux

package policy

import "errors"

// errWindowsOnly is returned by the enforcement entry points on platforms with
// no real implementation (currently macOS). Windows and Linux have their own
// files; this stub keeps the package compiling everywhere else.
var errWindowsOnly = errors.New("policy enforcement is not supported on this platform")

// Apply is a no-op stub on non-Windows platforms.
func Apply(cfg Config) error { return errWindowsOnly }

// Remove is a no-op stub on non-Windows platforms.
func Remove(cfg Config) error { return errWindowsOnly }

// Verify returns no statuses on non-Windows platforms.
func Verify(cfg Config) []Status { return nil }

// DetectBrowsers returns an empty map on non-Windows platforms.
func DetectBrowsers() map[Kind]bool { return map[Kind]bool{} }

// geckoBrowsers is the Firefox-family half of AllKinds. Nothing here writes any
// policy at all, so this is the shortest honest list rather than the family, and
// it discovers nothing: see policy_linux.go for what naming a browser in it
// claims.
func geckoBrowsers() []GeckoBrowser {
	return []GeckoBrowser{{Kind: Firefox, Name: "Firefox"}}
}

// resetGeckoBrowsers drops the cached scan on the platform that has one. Nothing
// is discovered or cached here, so it does nothing - it exists so the test helper
// that describes a machine reads the same on every platform.
func resetGeckoBrowsers() {}
