//go:build !windows && !linux

package scm

import "errors"

// These stubs let the service package compile on platforms with no real
// implementation (currently macOS). Windows and Linux have their own files.
var errWindowsOnly = errors.New("service control is not supported on this platform")

// Harden is a no-op stub on non-Windows platforms.
func Harden(name string) error { return errWindowsOnly }

// EnsureRunning is a no-op stub on non-Windows platforms.
func EnsureRunning(name string) (string, error) { return "", errWindowsOnly }

// Exists reports false on non-Windows platforms.
func Exists(name string) bool { return false }

// IsRunning reports false on non-Windows platforms.
func IsRunning(name string) bool { return false }

// SetDisabled is a no-op stub on non-Windows platforms.
func SetDisabled(v bool) error { return errWindowsOnly }

// IsDisabled reports false on non-Windows platforms.
func IsDisabled() bool { return false }

// SetUpdating is a no-op stub on non-Windows platforms.
func SetUpdating(v bool) error { return errWindowsOnly }

// IsUpdating reports false on non-Windows platforms.
func IsUpdating() bool { return false }

// AcquireSingleton always succeeds on non-Windows platforms.
func AcquireSingleton(name string) bool { return true }

// setPauseValue is a no-op stub on unsupported platforms.
func setPauseValue(v string) error { return errWindowsOnly }

// pauseValue reports no recorded pause on unsupported platforms.
func pauseValue() string { return "" }

// SetPasswordHash is a no-op stub on non-Windows platforms.
func SetPasswordHash(hash string) error { return errWindowsOnly }

// GetPasswordHash reports no stored hash on non-Windows platforms.
func GetPasswordHash() (string, bool) { return "", false }

// ClearPasswordHash is a no-op stub on non-Windows platforms.
func ClearPasswordHash() error { return errWindowsOnly }

// SetFrictionChars is a no-op stub on unsupported platforms.
func SetFrictionChars(n int) error { return errWindowsOnly }

// GetFrictionChars reports no challenge on unsupported platforms.
func GetFrictionChars() (int, bool) { return 0, false }

// ClearFrictionChars is a no-op stub on unsupported platforms.
func ClearFrictionChars() error { return errWindowsOnly }

// SetTrustedConfig is a no-op stub on unsupported platforms.
func SetTrustedConfig(data []byte) error { return errWindowsOnly }

// GetTrustedConfig reports no trusted config on unsupported platforms, so the
// on-disk file is used as-is.
func GetTrustedConfig() ([]byte, bool) { return nil, false }

// ClearTrustedConfig is a no-op stub on unsupported platforms.
func ClearTrustedConfig() error { return errWindowsOnly }

// ClearWrittenTargets is a no-op stub on unsupported platforms.
func ClearWrittenTargets() error { return errWindowsOnly }
