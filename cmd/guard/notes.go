package main

import (
	"fmt"

	"github.com/codepurse/extension-guard/internal/policy"
)

// printRestartNote says so when Firefox or Zen is open, because Mozilla's policy
// engine reads its settings once at startup and cannot be made to re-read them -
// see policy.GeckoRunning. Chrome, Edge and Brave are refreshed as part of
// applying the change, so they need nothing said about them; staying quiet about
// the others would mean reporting a lock that is not yet holding in the browser
// the user is looking at.
func printRestartNote() {
	running := policy.GeckoRunning()
	if len(running) == 0 {
		return
	}
	verb, subject := "picks", "it starts"
	if len(running) > 1 {
		verb, subject = "pick", "they start"
	}
	fmt.Printf("(%s %s this up the next time %s; the other browsers already have it)\n",
		policy.BrowserNames(running), verb, subject)
}
