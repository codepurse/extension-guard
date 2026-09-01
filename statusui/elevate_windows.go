//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// errElevationCancelled is returned when the user dismisses the UAC prompt.
var errElevationCancelled = errors.New("elevation cancelled")

var (
	modshell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = modshell32.NewProc("ShellExecuteExW")
)

const (
	seeMaskNoCloseProcess = 0x00000040 // keep hProcess open so we can wait on it
	swHide                = 0          // run the elevated guard with no window
	// swShowNormal gives the elevated guard a console of its own. guard.exe is a
	// console-subsystem binary, so a shown window means a real console with a real
	// stdin - which is the only place the typing challenge can be answered when the
	// window is the one asking. See App.execGuard.
	swShowNormal = 1
)

// shellExecuteInfo mirrors the Win32 SHELLEXECUTEINFOW struct. Field order and
// alignment must match exactly; cbSize is set to unsafe.Sizeof at call time.
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIconOrMon   uintptr // union: hIcon / hMonitor
	hProcess     uintptr
}

// runElevatedAndWait launches exe with args via a UAC ("runas") prompt, waits
// for the elevated process to finish, and returns its exit code. It returns
// errElevationCancelled if the user declines the prompt.
func runElevatedAndWait(exe string, args []string, showConsole bool) (int, error) {
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	params, err := syscall.UTF16PtrFromString(buildArgs(args))
	if err != nil {
		return 0, err
	}

	show := int32(swHide)
	if showConsole {
		show = int32(swShowNormal)
	}

	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		nShow:        show,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))

	ret, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		// On failure hInstApp holds the error code; ERROR_CANCELLED (1223) means
		// the user dismissed the UAC prompt.
		if info.hInstApp == uintptr(windows.ERROR_CANCELLED) ||
			errors.Is(callErr, syscall.Errno(windows.ERROR_CANCELLED)) {
			return 0, errElevationCancelled
		}
		return 0, fmt.Errorf("ShellExecuteEx failed (code %d): %v", info.hInstApp, callErr)
	}
	if info.hProcess == 0 {
		return 0, errors.New("elevated process did not start")
	}

	h := windows.Handle(info.hProcess)
	defer windows.CloseHandle(h)
	if _, err := windows.WaitForSingleObject(h, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return 0, err
	}
	return int(code), nil
}

// buildArgs turns an argument list into a Windows command line that parses back
// to exactly that list.
//
// This has to be exact, not merely good enough for spaces, because several of
// these arguments are free-form text: a window title someone typed, a label, a
// path from the file picker, and a Store app's DisplayName - which comes from a
// registry key any standard user can write. The command line it builds is handed
// to an *elevated* guard.exe, so a value that escapes its own quoting stops being
// a value and becomes arguments: `a\" -extensions blocknsfw select "` would
// redirect the invocation to `select`, which rewrites the enforced config with no
// password. That is the one thing the password gate exists to prevent.
//
// The previous implementation wrapped each argument in quotes and doubled any
// quote inside it, which handles spaces but not backslashes - and `\"` is a
// literal quote to the parser, so a trailing backslash escaped the closing quote
// and let the rest of the argument be read as new arguments. syscall.EscapeArg
// implements the full CommandLineToArgvW convention (backslash runs before a
// quote and at the end of the argument are doubled), so no input can break out.
func buildArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = syscall.EscapeArg(a)
	}
	return strings.Join(q, " ")
}
