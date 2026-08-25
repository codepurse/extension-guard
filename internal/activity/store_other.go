//go:build !windows

package activity

import (
	"fmt"
	"os"
)

// The non-Windows half of the log's storage. It is simpler than the Windows one
// for a reason worth stating rather than leaving as an apparent oversight: the
// only writer that needs to be unprivileged on Windows is the refused-launch
// handler, and that mechanism (Image File Execution Options) has no counterpart
// here - internal/policy/appblock_other.go reports application rules as
// unenforceable on this platform. Every event that can be recorded on Linux is
// recorded by the root-owned daemon or by a sudo'd CLI, so the file only needs to
// be root-writable and world-readable.
//
// World-readable is the same deliberate choice it is on Windows: the person being
// filtered should be able to read the record kept about them.

// defaultDir puts the log under /var/log, where a daemon's log belongs, rather
// than next to the state file in /etc/extension-guard (see internal/scm).
func defaultDir() string { return "/var/log/extension-guard" }

// ensure creates the log directory and file if they are missing, root-owned and
// world-readable. An unprivileged caller fails here and carries on, appending
// nothing - matching the Windows behaviour, where the same call succeeds only for
// SYSTEM or an administrator.
func ensure(dir, path string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}
	// O_APPEND, not O_TRUNC: this runs on every start, and the one thing it must
	// never do is empty the record it exists to protect.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("create log: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("create log: %w", err)
	}
	// Chmod explicitly: the mode passed to OpenFile is masked by umask, and a
	// daemon started with a restrictive umask would otherwise create a log its own
	// user could not read.
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("secure log: %w", err)
	}
	return nil
}
