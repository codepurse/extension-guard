//go:build windows

package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SwapFiles replaces each live binary in dir with its staged "<name>.new"
// counterpart (staged maps asset name -> staged path, as returned by
// Release.Stage).
//
// Windows won't let you overwrite or delete a running .exe, but it *will* let you
// rename one - even the caller's own image. So for each file we move the live
// binary aside to "<name>.old" and rename the staged ".new" into its place. The
// running service, watchdog, and status window keep executing from the
// renamed-aside image until they restart; the ".old" files are scheduled for
// deletion on the next reboot (a loaded image can't be unlinked immediately). If
// a rename fails partway we roll back the swaps already done, so a half-updated
// install is never left behind.
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
		_ = os.Remove(old) // clear a leftover from a previous update
		if _, err := os.Stat(target); err == nil {
			if err := os.Rename(target, old); err != nil {
				rollback()
				return fmt.Errorf("move %s aside: %w", name, err)
			}
		}
		if err := os.Rename(newPath, target); err != nil {
			_ = os.Rename(old, target) // restore this one, then unwind the rest
			rollback()
			return fmt.Errorf("install %s: %w", name, err)
		}
		done = append(done, name)
		scheduleDeleteOnReboot(old)
	}
	return nil
}

var procMoveFileExW = windows.NewLazySystemDLL("kernel32.dll").NewProc("MoveFileExW")

const moveFileDelayUntilReboot = 0x4 // MOVEFILE_DELAY_UNTIL_REBOOT

// scheduleDeleteOnReboot asks Windows to delete path on the next boot, when no
// process holds the old image any more. Best-effort: on failure the stale
// "<name>.old" is simply removed by CleanupOld on a later start.
func scheduleDeleteOnReboot(path string) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	// lpNewFileName == NULL + MOVEFILE_DELAY_UNTIL_REBOOT means "delete at boot".
	procMoveFileExW.Call(uintptr(unsafe.Pointer(p)), 0, moveFileDelayUntilReboot)
}

// CleanupOld removes leftover "<name>.old" binaries in dir. Safe to call on
// startup: a file still held by a running image just fails to delete and is
// retried next time.
func CleanupOld(dir string) {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.old"))
	for _, m := range matches {
		_ = os.Remove(m)
	}
}
