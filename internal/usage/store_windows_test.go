//go:build windows

package usage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These tests are about the permissions rather than the counting: the ledger
// decides whether a daily limit means anything, and it only means something
// because the person it applies to cannot edit it. The unit tests substitute a
// plain file creator to keep temp directories deletable, so this is the one place
// the real DACL is exercised.

// The security property in one assertion: Users may read the ledger and do nothing
// else to it. Read is deliberate - the status window is unprivileged and has to be
// able to show how much of today is left. Everything else on this list would let
// the person being limited hand themselves the evening back.
func TestUsersMayOnlyReadTheLedger(t *testing.T) {
	dir, path := tempLedger(t)
	if err := ensure(dir, path); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	mask := grantedTo(t, path, windows.WinBuiltinUsersSid)
	if mask&windows.FILE_GENERIC_READ != windows.FILE_GENERIC_READ {
		t.Errorf("Users are not granted read (mask 0x%08x), so the status window could not show what is left", uint32(mask))
	}
	for name, bit := range map[string]windows.ACCESS_MASK{
		"FILE_WRITE_DATA":  windows.FILE_WRITE_DATA,  // rewrite the counters
		"FILE_APPEND_DATA": windows.FILE_APPEND_DATA, // make the file unparseable
		"DELETE":           windows.DELETE,           // remove it, which reads as a fresh day
		"WRITE_DAC":        windows.WRITE_DAC,        // grant themselves the above
		"WRITE_OWNER":      windows.WRITE_OWNER,
	} {
		if mask&bit != 0 {
			t.Errorf("Users are granted %s, so a daily limit can be reset by the person it applies to", name)
		}
	}
}

// SYSTEM has to keep full control whatever else the DACL says: it is the account
// the service runs as, and it is the only writer that matters.
func TestSystemKeepsFullControlOfTheLedger(t *testing.T) {
	dir, path := tempLedger(t)
	if err := ensure(dir, path); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	for _, want := range []struct {
		name string
		bit  windows.ACCESS_MASK
	}{
		{"FILE_WRITE_DATA", windows.FILE_WRITE_DATA},
		{"DELETE", windows.DELETE},
	} {
		if mask := grantedTo(t, path, windows.WinLocalSystemSid); mask&want.bit == 0 {
			t.Errorf("SYSTEM is not granted %s, so the service could not update the ledger", want.name)
		}
	}
}

// The production sequence with the real permissions code in the loop: provision,
// count, flush, and read it back. A rewrite is a temp file and a rename, and the
// rename has to keep working against a file whose DACL has been locked down -
// which is the part a mask assertion cannot show.
func TestFlushRepeatedlyWithRealPermissions(t *testing.T) {
	d, _ := tempLedger(t)
	prevDir := dir
	t.Cleanup(func() { dir = prevDir })
	dir = d

	if err := Provision(); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	tr := NewTracker()
	start := time.Date(2026, 8, 20, 19, 0, 0, 0, time.Local)
	now := start
	for round := 0; round < 3; round++ {
		for i := 0; i < 10; i++ {
			now = now.Add(time.Second)
			tr.Observe(now, day1, []string{"games"}, nil)
		}
		if err := tr.Flush(); err != nil {
			t.Fatalf("flush %d: %v", round, err)
		}
	}

	// Ten seconds a round, three rounds, less the one that established the baseline.
	led, state := Load()
	if state != StateOK {
		t.Fatalf("Load: state %s, want ok", state)
	}
	if got := led.Spent(day1)["games"]; got != 29*time.Second {
		t.Errorf("recorded %s, want 29s", got)
	}
	// And the permissions survived being renamed over, rather than being whatever
	// the last temp file happened to inherit.
	if mask := grantedTo(t, Path(), windows.WinBuiltinUsersSid); mask&windows.FILE_WRITE_DATA != 0 {
		t.Error("after a rename the ledger grants Users write")
	}
}

// tempLedger makes a directory the test owns and returns it with the ledger path
// inside it.
//
// Deliberately not t.TempDir: secure stamps a protected DACL, and the framework's
// own cleanup would fail to remove a directory holding a file it no longer has
// delete rights to. The cleanup below drops the DACL first, which an object's
// owner may always do however locked down the object is.
func tempLedger(t *testing.T) (string, string) {
	t.Helper()
	base, err := os.MkdirTemp("", "eg-usage-")
	if err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(base, "ExtensionGuard")
	p := filepath.Join(d, fileName)
	t.Cleanup(func() {
		openUp(p)
		openUp(filepath.Join(d, tempName))
		openUp(d)
		if err := os.RemoveAll(base); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
	return d, p
}

// grantedTo totals the access one well-known account is allowed on an object, by
// walking the DACL the guard actually wrote rather than the one it meant to write.
func grantedTo(t *testing.T, path string, wellKnown windows.WELL_KNOWN_SID_TYPE) windows.ACCESS_MASK {
	t.Helper()
	want, err := windows.CreateWellKnownSid(wellKnown)
	if err != nil {
		t.Fatalf("sid: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read security descriptor: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("read dacl: %v", err)
	}
	if dacl == nil {
		t.Fatal("the object has no DACL, so everyone has full control")
	}

	var mask windows.ACCESS_MASK
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("read ace %d: %v", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(want) {
			mask |= ace.Mask
		}
	}
	return mask
}

// openUp drops an object's DACL so the test can delete what it made. An owner
// always holds WRITE_DAC whatever the DACL says, which is why this works after
// secure has locked the object down.
func openUp(path string) {
	_ = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, nil, nil,
	)
}
