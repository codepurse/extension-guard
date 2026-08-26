//go:build !windows

package usage

import (
	"fmt"
	"os"
)

// The non-Windows half of the ledger's storage. Time limits are measured by
// watching processes, which is Windows-only (see internal/policy/appblock_other.go),
// so on this platform the ledger only ever holds what a test puts in it. The
// permissions are still stated rather than left to the umask, because a file the
// daemon writes and an unprivileged status tool reads has to be readable by both.

// defaultDir puts the ledger alongside the activity log, under /var/lib rather
// than /var/log: this is state the guard reads back and acts on, not a record of
// what happened.
func defaultDir() string { return "/var/lib/extension-guard" }

// ensure creates the directory and the ledger file, root-owned and world-readable.
// An unprivileged caller fails here and carries on, exactly as it does on Windows.
func ensure(dir, path string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create usage directory: %w", err)
	}
	// O_APPEND rather than O_TRUNC: this runs on every start, and emptying a day's
	// counters would hand back a budget that had been spent.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("create usage file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("create usage file: %w", err)
	}
	return secure(path)
}

// secure makes the ledger world-readable and writable only by its owner. Chmod is
// explicit because the mode passed to OpenFile is masked by umask, and a daemon
// started with a restrictive one would otherwise create a ledger the status tool
// could not read.
func secure(path string) error {
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("secure usage file: %w", err)
	}
	return nil
}
