//go:build !windows && !linux

package policy

// ApplyHardening is a no-op stub on unsupported platforms.
func ApplyHardening(cfg Config) error { return errWindowsOnly }

// VerifyHardening returns no statuses on unsupported platforms.
func VerifyHardening(cfg Config) []Status { return nil }

// RemoveHardening is a no-op stub on unsupported platforms.
func RemoveHardening(cfg Config) error { return errWindowsOnly }
