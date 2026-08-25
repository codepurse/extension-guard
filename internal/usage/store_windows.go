//go:build windows

package usage

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// This file decides who can read and write the ledger. The package comment says
// what the permissions are meant to be; the DACL below is what makes it true.
//
// It is deliberately close to internal/activity's store, with one difference that
// is the whole point: Users get read and *not* append. The log has an unprivileged
// writer and this does not, so the narrow concession that file makes is not one
// this file has to make.

// defaultDir is the same directory the activity log lives in, for the same reason:
// ProgramData rather than the install directory, which the updater renames files
// in and out of during a swap. State that has to survive an upgrade has no
// business living where the upgrade happens.
func defaultDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "ExtensionGuard")
}

// ensure creates the directory and the ledger file and stamps the file's
// permissions. Only privileged code reaches it (see Provision).
//
// It deliberately does not re-stamp the directory. internal/activity owns that
// DACL - the two packages share the directory, and the log needs Users to hold
// append on it while the ledger does not, so having both write it would mean
// whichever ran last decided. The ledger's own file carries a protected DACL, so
// what the directory grants does not reach it either way.
func ensure(dir, path string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create usage directory: %w", err)
	}
	// O_APPEND rather than O_TRUNC, on a file this only ever opens to create: this
	// runs on every service start, and emptying a day's counters would hand back a
	// budget that had been spent.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("create usage file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("create usage file: %w", err)
	}
	clearReadOnly(path)
	return secure(path)
}

// secure replaces the object's DACL with SYSTEM and Administrators full control
// plus Users read, marks it protected so nothing is inherited from ProgramData -
// which grants ordinary users rights this file should not carry - and reassigns
// the owner.
//
// Reassigning the owner is not tidiness. An owner holds WRITE_DAC whatever the
// DACL says, so a file somebody else created first - dropping one at this path by
// hand before the guard is installed is enough - would leave them able to widen
// its permissions again at will. This is also why a rewrite stamps the temp file
// before renaming it into place: the new file must not arrive owned by whoever
// happened to create it.
func secure(path string) error {
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

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		grant(windows.GENERIC_ALL, system, windows.TRUSTEE_IS_USER),
		grant(windows.GENERIC_ALL, admins, windows.TRUSTEE_IS_GROUP),
		// Read only. Everything the person being limited needs - how much of today
		// they have used - is in here, and none of what they could do with write
		// access to it is anything the guard should allow.
		grant(windows.FILE_GENERIC_READ, users, windows.TRUSTEE_IS_GROUP),
	}, nil)
	if err != nil {
		return fmt.Errorf("build acl: %w", err)
	}

	const dacl = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION

	// Taking ownership needs a privilege SYSTEM has and an ordinary administrator
	// may not, so it is attempted first and the plain DACL write is the fallback.
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

// grant builds one allow entry for a SID. Nothing here is inheritable: every
// object this package stamps is a file.
func grant(mask windows.ACCESS_MASK, sid *windows.SID, kind windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  kind,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// clearReadOnly drops the read-only attribute if it is set. A read-only ledger
// cannot be replaced by the rename a rewrite ends with, so an administrator who
// set the attribute would otherwise freeze the counters where they stand - which
// is a bypass if they stand at zero.
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
