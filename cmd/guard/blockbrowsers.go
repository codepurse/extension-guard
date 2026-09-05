package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/codepurse/extension-guard/internal/activity"
	"github.com/codepurse/extension-guard/internal/enforce"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
)

// blockBrowsersCmd turns the unsupported-browser block on or off.
//
// The gate lands the usual way round: on only adds protection, so it costs
// administrator rights and nothing more, while off hands back a way round every
// locked extension and takes the password.
func blockBrowsersCmd(cfg policy.Config, cfgPath string, on bool, password string) {
	if cfg.BlockUnsupported == on {
		fmt.Printf("unsupported browsers are already %s\n", onOff(on))
		return
	}
	if !on && !scm.IsPaused() {
		requirePassword(password, "letting unsupported browsers run again")
	}

	cfg.BlockUnsupported = on
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(cfg))

	kind := activity.BrowsersUnblocked
	if on {
		kind = activity.BrowsersBlocked
	}
	activity.Record(activity.Event{Kind: kind})

	found := policy.UnmanagedBrowsers()
	if on {
		if len(found) == 0 {
			fmt.Println("unsupported browsers: blocked (none are installed here right now)")
			fmt.Println("one installed later is blocked on the next check, without anything to set again")
			return
		}
		fmt.Printf("unsupported browsers: blocked (%s)\n", browserLabels(found))
		return
	}
	fmt.Println("unsupported browsers: allowed")
	if len(found) > 0 {
		// Said plainly, because this is the moment the promise stops being true.
		fmt.Printf("%s carries none of the locked extensions, so everything they filter is reachable through it\n",
			browserLabels(found))
	}
}

// browserLabels names the browsers the way a sentence does. policy.BrowserNames
// is for the Gecko forks and takes a different type, so this is the same job for
// the ones discovered on the machine.
func browserLabels(list []policy.InstalledBrowser) string {
	names := make([]string, 0, len(list))
	for _, b := range list {
		names = append(names, b.Label())
	}
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func onOff(on bool) string {
	if on {
		return "blocked"
	}
	return "allowed"
}
