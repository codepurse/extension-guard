//go:build windows

package activity

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// This file is where the log's permissions are actually decided. The package
// comment says what they are meant to be; the DACL below is what makes it true,
// and the masks are load-bearing in a way that is easy to break by tidying, so
// each one says why it is there.

// defaultDir puts the log under ProgramData rather than beside the binaries. The
// install directory is under Program Files, which the updater renames files in
// and out of during a swap - a record of what happened has no business living
// somewhere a version upgrade moves things around.
func defaultDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "ExtensionGuard")
}

// appendOnlyMask is what Users get on the log: read it, and add to the end of it.
//
// The exact bits are load-bearing, because they have to line up with what Go asks
// for when it opens a file with O_APPEND: FILE_APPEND_DATA together with
// FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA, READ_CONTROL and SYNCHRONIZE (see
// syscall.Open in the Windows runtime - it clears GENERIC_WRITE and sets exactly
// those). Granting less makes an ordinary append fail with access denied, so a
// blocked launch would quietly stop recording itself. Granting FILE_WRITE_DATA as
// well would defeat the whole point: that is the bit that allows overwriting what
// is already in the file.
//
// FILE_GENERIC_READ brings READ_CONTROL and SYNCHRONIZE with it, which is why
// they are not named again here.
const appendOnlyMask windows.ACCESS_MASK = windows.FILE_GENERIC_READ |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.FILE_WRITE_EA

// ensure creates the log directory and file if they are missing and stamps both
// with the DACL described in the package comment. Only privileged code reaches it
// (see Provision); an unprivileged caller fails at the first write and its events
// are dropped rather than landing in a file it would own.
//
// It re-applies the DACL on every call rather than only on creation, for the same
// reason the service re-applies the browser policy every cycle: a permission
// someone widened by hand should not stay widened.
//
// The order is load-bearing. The file is created *before* the directory is locked
// down, because creating a file in a directory needs FILE_ADD_FILE on it - which
// is precisely the right the directory's DACL is about to withhold from everyone
// but SYSTEM and Administrators. Tightening first happens to work for the caller
// that matters (SYSTEM holds every right, so it can still create), but it makes
// creation depend on the guard's own grant to itself. Create, then lock.
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
	// Users hold FILE_WRITE_ATTRIBUTES (they must, to append at all), and that is
	// enough to set the read-only attribute - which would stop every writer,
	// including SYSTEM, until it was cleared. Clear it here so that trick costs
	// the person trying it nothing more than a restart of the service.
	clearReadOnly(path)
	if err := applyDACL(path, false); err != nil {
		return fmt.Errorf("secure log: %w", err)
	}
	if err := applyDACL(dir, true); err != nil {
		return fmt.Errorf("secure log directory: %w", err)
	}
	return nil
}

// applyDACL replaces the object's DACL with SYSTEM and Administrators full
// control plus Users read-and-append, and marks it protected so nothing is
// inherited from ProgramData - which grants ordinary users create rights that
// would let them drop a file of their own next to the log.
//
// For the directory the entries are inheritable and Users also get execute, which
// on a directory is the right to traverse and list it. A file created in the
// directory therefore starts with the permissions we want even before ensure gets
// to stamp it explicitly.
func applyDACL(path string, container bool) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("local system sid: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("administrators sid: %w", err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return fmt.Errorf("users sid: %w", err)
	}

	inheritance := uint32(windows.NO_INHERITANCE)
	userMask := appendOnlyMask
	if container {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
		userMask |= windows.FILE_GENERIC_EXECUTE
	}

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		grant(windows.GENERIC_ALL, inheritance, system, windows.TRUSTEE_IS_USER),
		grant(windows.GENERIC_ALL, inheritance, admins, windows.TRUSTEE_IS_GROUP),
		grant(userMask, inheritance, users, windows.TRUSTEE_IS_GROUP),
	}, nil)
	if err != nil {
		return fmt.Errorf("build acl: %w", err)
	}

	const dacl = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION

	// Reassign the owner along with the DACL. An owner always holds WRITE_DAC
	// whatever the DACL says, so an object somebody else created first - dropping a
	// file at this path by hand before the guard is installed is enough - would
	// leave them able to widen its permissions again at will. Handing ownership to
	// Administrators closes that.
	//
	// Reassigning an owner takes a privilege SYSTEM has and an ordinary account
	// does not, so it is attempted first and the plain DACL write is the fallback.
	// Failing to take ownership must not cost us the permissions themselves.
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		dacl|windows.OWNER_SECURITY_INFORMATION,
		admins, nil, acl, nil,
	); err == nil {
		return nil
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, dacl, nil, nil, acl, nil)
}

// grant builds one allow entry for a SID.
func grant(mask windows.ACCESS_MASK, inheritance uint32, sid *windows.SID, kind windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  kind,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// clearReadOnly drops the read-only attribute if it is set. Best-effort: if it
// cannot be cleared the log is stuck until someone clears it by hand, which is
// still better than the alternative of not noticing.
func clearReadOnly(path string) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_READONLY == 0 {
		return
	}
	_ = windows.SetFileAttributes(p, attrs&^windows.FILE_ATTRIBUTE_READONLY)
}
