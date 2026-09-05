//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// MessageBoxW flags: an error icon, always on top, and brought to the front,
// because the window has no parent to sit over - the shell launched what the user
// double-clicked and got us instead.
const (
	mbOK            = 0x00000000
	mbIconError     = 0x00000010
	mbSetForeground = 0x00010000
	mbTopMost       = 0x00040000
)

// notifyBlocked tells the user, in the session that tried to launch the app, that
// the launch was refused. A message box rather than console output: this runs
// because Windows started the guard in place of a program the user
// double-clicked, so there is no console to print to, and silence would look like
// a broken shortcut.
//
// Failure here needs no error path - if the message cannot be shown, the
// application is still blocked, which is the part that matters.
func notifyBlocked(name string) {
	title, err := windows.UTF16PtrFromString("Blocked by Ward")
	if err != nil {
		return
	}
	body, err := windows.UTF16PtrFromString(fmt.Sprintf(
		"%s is blocked right now.\r\n\r\nOpen Ward to see what is blocked, or to unblock it with the password.", name))
	if err != nil {
		return
	}
	if _, err := windows.MessageBox(0, body, title, mbOK|mbIconError|mbSetForeground|mbTopMost); err != nil {
		// No window station to draw on (a service or scheduled task tried the
		// launch). Say it on stderr instead, in case something is capturing it.
		fmt.Fprintf(os.Stderr, "%s is blocked by Ward\n", name)
	}
}
