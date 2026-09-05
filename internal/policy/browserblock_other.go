//go:build !windows

package policy

import "errors"

// errWindowsOnly is what every Windows-only mechanism returns here. It is a
// refusal rather than a silent no-op: a stub that quietly blocked nothing would
// let the status window report a hole as closed.
var errWindowsOnly = errors.New("this is only implemented on Windows")

// Blocking a browser's executable is Windows-only. The mechanism is Image File
// Execution Options, which has no equivalent here: the Linux port would need a
// different one - a wrapper script, or a systemd unit - and inventing a stub that
// silently blocked nothing would let the status window report a hole as closed.
//
// So this refuses, and the enforcer reports the setting as unavailable rather
// than as enforced.

// ApplyBrowserBlocks does nothing when the setting is off, and refuses when it is
// on. Nothing was written, so nothing is left behind either way.
func ApplyBrowserBlocks(cfg Config) error {
	if !cfg.BlockUnsupported {
		return nil
	}
	return errWindowsOnly
}

// RemoveBrowserBlocks has nothing to lift.
func RemoveBrowserBlocks() error { return nil }

// BrowserBlocked always reports false: nothing here writes a block.
func BrowserBlocked(image string) bool { return false }
