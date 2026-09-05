package main

import (
	"os"
	"strings"

	"github.com/codepurse/extension-guard/internal/activity"
)

// blockedCmd is what a blocked browser's launch turns into: the guard is
// registered as its debugger (see internal/policy/browserblock_windows.go), so
// Windows starts this instead of the browser, with the browser's own command line
// appended.
//
// It must be the least demanding command there is - no config, no admin, no
// registry - because it runs in that user's session on every attempt, and
// anything that can fail here turns a block into a crash somebody reports as a
// bug.
func blockedCmd(args []string) {
	name := "This browser"
	for _, a := range args {
		if s := strings.Trim(strings.TrimSpace(a), `"`); s != "" {
			name = baseNameOf(s)
			break
		}
	}
	// Recorded before the message box, which blocks until it is dismissed. This is
	// the one event nobody else can report: the launch block stops the program
	// before it exists, so there is no process for the service to notice.
	activity.Record(activity.Event{Kind: activity.LaunchBlocked, Target: name})
	notifyBlocked(name)
	// Non-zero: the launch did not do what the caller asked. Nothing reads this
	// today, but a script starting a blocked browser should see a failure.
	os.Exit(1)
}

// baseNameOf is the file-name part of a Windows path, for the message.
func baseNameOf(p string) string {
	p = strings.TrimRight(p, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
