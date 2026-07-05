//go:build !windows

package updater

import (
	"fmt"
	"os"
	"path/filepath"
)

// SwapFiles replaces each live binary in dir with its staged "<name>.new"
// counterpart (staged maps asset name -> staged path, as returned by
// Release.Stage).
//
// On Unix a running binary can be replaced by rename - the open image keeps
// executing from the now-unlinked inode - so this is a straight atomic rename
// with the same move-aside-and-rollback safety net as the Windows path. The
// ".old" files are removed immediately, since Unix has no objection to unlinking
// a busy binary.
func SwapFiles(dir string, staged map[string]string) error {
	var done []string // names swapped so far, for rollback
	rollback := func() {
		for _, name := range done {
			target := filepath.Join(dir, name)
			_ = os.Remove(target)
			_ = os.Rename(target+".old", target)
		}
	}
	for name, newPath := range staged {
		target := filepath.Join(dir, name)
		old := target + ".old"
		_ = os.Remove(old)
		if _, err := os.Stat(target); err == nil {
			if err := os.Rename(target, old); err != nil {
				rollback()
				return fmt.Errorf("move %s aside: %w", name, err)
			}
		}
		if err := os.Rename(newPath, target); err != nil {
			_ = os.Rename(old, target)
			rollback()
			return fmt.Errorf("install %s: %w", name, err)
		}
		done = append(done, name)
		_ = os.Remove(old)
	}
	return nil
}

// CleanupOld removes leftover "<name>.old" binaries in dir.
func CleanupOld(dir string) {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.old"))
	for _, m := range matches {
		_ = os.Remove(m)
	}
}
