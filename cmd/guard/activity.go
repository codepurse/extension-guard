package main

import (
	"fmt"
	"time"

	"github.com/codepurse/extension-guard/internal/activity"
)

// This file holds `guard activity`, which prints the record of what the guard did
// and what was done to it. Everything else in the CLI answers "what is enforced
// now"; this is the one command that answers "what happened".
//
// It needs no config, no admin and no password. That is deliberate on all three
// counts: the person being filtered is meant to be able to read the record kept
// about them, and a command that needed elevation to answer that would make the
// transparency theoretical.

// defaultActivityCount is how many entries the command shows when -n is not
// given. Enough to cover a day or two of normal use without scrolling past the
// point anyone is reading.
const defaultActivityCount = 30

// activityCmd prints the most recent entries, newest first.
func activityCmd(count int) {
	if count <= 0 {
		count = defaultActivityCount
	}
	events := activity.Recent(count)
	if len(events) == 0 {
		fmt.Println("nothing recorded yet")
		fmt.Printf("(the record lives at %s, and is written by the guard service)\n", activity.Path())
		return
	}
	for _, ev := range events {
		line := fmt.Sprintf("  %s  %s",
			ev.Time.Local().Format("2006-01-02 15:04:05"),
			activity.Describe(ev))
		if ev.Detail != "" {
			line += " - " + ev.Detail
		}
		if ev.Actor != "" {
			line += fmt.Sprintf(" [%s]", ev.Actor)
		}
		fmt.Println(line)
	}
	// Close with the path. Someone reading a run of "wrong password entered" lines
	// will want the raw record, and having to ask where it is defeats the point of
	// its being readable at all.
	fmt.Printf("\n(%d shown, newest first, from %s)\n", len(events), activity.Path())
	if oldest := events[len(events)-1].Time; !oldest.IsZero() {
		fmt.Printf("(the oldest entry shown is from %s)\n", oldest.Local().Format(time.RFC1123))
	}
}
