//go:build !windows && !linux

package policy

// ApplyDomains is a no-op stub on unsupported platforms.
func ApplyDomains(cfg Config) error { return errWindowsOnly }

// VerifyDomains returns no statuses on unsupported platforms.
func VerifyDomains(cfg Config) []Status { return nil }

// RemoveDomains is a no-op stub on unsupported platforms.
func RemoveDomains(cfg Config) error { return errWindowsOnly }
