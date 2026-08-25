//go:build windows

package activity

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// goAppendAccess is the access mask the Go runtime requests when a file is opened
// with O_WRONLY|O_APPEND: it clears GENERIC_WRITE and sets exactly these bits
// (see syscall.Open in src/syscall/syscall_windows.go).
//
// It is written out here rather than derived, because the point of the test below
// is to fail loudly if the two ever drift apart. Grant Users less than this and
// the append that records a refused launch fails with access denied - silently,
// in the one code path that has no way to report anything.
const goAppendAccess windows.ACCESS_MASK = windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.FILE_WRITE_EA |
	windows.STANDARD_RIGHTS_WRITE |
	windows.SYNCHRONIZE

// The Users mask is the whole append-only property, expressed as bits. Both
// halves of it are worth pinning: too few bits and an unprivileged append breaks,
// one bit too many and the log stops being append-only.
func TestAppendOnlyMaskGrantsExactlyWhatAnAppendNeeds(t *testing.T) {
	if missing := goAppendAccess &^ appendOnlyMask; missing != 0 {
		t.Errorf("Users are not granted 0x%08x, so an ordinary append would fail with access denied", uint32(missing))
	}
	for name, bit := range map[string]windows.ACCESS_MASK{
		"FILE_WRITE_DATA": windows.FILE_WRITE_DATA, // overwrite what is already there
		"DELETE":          windows.DELETE,          // remove the file outright
		"WRITE_DAC":       windows.WRITE_DAC,       // grant themselves the above
		"WRITE_OWNER":     windows.WRITE_OWNER,
	} {
		if appendOnlyMask&bit != 0 {
			t.Errorf("Users are granted %s, so the log is no longer append-only", name)
		}
	}
}

// ensure has to produce a file that the same append Record performs can actually
// write to, and it runs on every start, so it must never empty the record it just
// found.
func TestEnsureCreatesALogThatCanBeAppendedTo(t *testing.T) {
	// Deliberately not t.TempDir: ensure stamps a protected DACL, and the test
	// framework's own cleanup would fail to remove a directory it no longer holds
	// delete rights in. The cleanup below drops the DACL first, which an object's
	// owner may always do however locked down the object is.
	base, err := os.MkdirTemp("", "eg-activity-")
	if err != nil {
		t.Fatal(err)
	}
	logDir := filepath.Join(base, "ExtensionGuard")
	p := filepath.Join(logDir, logName)
	t.Cleanup(func() {
		openUp(p)
		openUp(logDir)
		if err := os.RemoveAll(base); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	if err := ensure(logDir, p); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	// The same open appendLine uses: append only, and no O_CREATE.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("cannot append to the log ensure just created: %v", err)
	}
	if _, err := f.WriteString("{}\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := ensure(logDir, p); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{}\n" {
		t.Errorf("the log holds %q after a second ensure, want the line already written", b)
	}
}

// openUp drops an object's DACL so the test can delete what it made. An owner
// always holds WRITE_DAC whatever the DACL says, which is why this works after
// ensure has locked the object down.
func openUp(path string) {
	_ = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, nil, nil,
	)
}

// The production sequence, with the real permissions code in the loop: the
// service provisions the store, something records an event, and the window reads
// it back. The unit tests substitute a plain file creator to keep temp
// directories deletable, so this is the one place all three meet.
func TestProvisionRecordAndReadBackWithRealPermissions(t *testing.T) {
	base, err := os.MkdirTemp("", "eg-activity-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	restore(t)
	dir = filepath.Join(base, "ExtensionGuard")
	ensureFile = ensure // the real one, DACL and all
	t.Cleanup(func() {
		openUp(filepath.Join(dir, logName))
		openUp(dir)
		if err := os.RemoveAll(base); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	Enable(ActorService)
	if err := Provision(); err != nil {
		t.Fatalf("provision: %v", err)
	}
	Record(Event{Kind: LaunchBlocked, Target: "steam.exe"})
	Record(Event{Kind: ProtectionPaused})

	got := Recent(10)
	if len(got) != 2 {
		t.Fatalf("read back %d events, want the 2 recorded", len(got))
	}
	if got[0].Kind != ProtectionPaused {
		t.Errorf("newest event is %q, want %q", got[0].Kind, ProtectionPaused)
	}
	if got[1].Kind != LaunchBlocked || got[1].Target != "steam.exe" {
		t.Errorf("oldest event is %+v, want a blocked launch of steam.exe", got[1])
	}
	if got[0].Actor != ActorService {
		t.Errorf("actor is %q, want %q", got[0].Actor, ActorService)
	}
	if Describe(got[1]) == got[1].Kind {
		t.Error("the event read back has no sentence; Describe fell through")
	}
}
