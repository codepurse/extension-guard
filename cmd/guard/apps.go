package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/codepurse/extension-guard/internal/enforce"
	"github.com/codepurse/extension-guard/internal/guardsvc"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
)

// This file holds the commands for the application block list. They mirror the
// domain commands deliberately: adding a block only strengthens protection so it
// costs admin and nothing more, while lifting one weakens it and takes the
// password.

// appsCmd lists the block list and whether each entry is being enforced right
// now. Read-only and admin-free.
func appsCmd(cfg policy.Config) {
	if !cfg.AnyApps() {
		fmt.Println("no applications blocked; add one with `guard block-app \"C:\\Games\\Steam\\steam.exe\"`")
		return
	}
	active := activeNow(cfg)
	blockedNow := make(map[string]bool)
	for _, a := range active.BlockedApps() {
		blockedNow[strings.ToLower(a.Kind)+"|"+strings.ToLower(a.Value)] = true
	}

	fmt.Printf("  %-46s %-7s %-8s %s\n", "app", "kind", "state", "note")
	for _, a := range cfg.Apps {
		n, err := policy.NormalizeApp(a.Kind, a.Value, a.Label)
		if err != nil {
			fmt.Printf("  %-46s %-7s %-8s %v\n", a.Value, a.Kind, "invalid", err)
			continue
		}
		state, note := "blocked", n.Summary()
		switch {
		case a.Disabled:
			state, note = "off", "switched off"
		case !blockedNow[strings.ToLower(n.Kind)+"|"+strings.ToLower(n.Value)]:
			state, note = "idle", "outside its block's window"
		}
		fmt.Printf("  %-46s %-7s %-8s %s\n", n.Display(), n.Kind, state, note)
	}
}

// blockAppCmd adds an application to the block list and enforces it immediately.
// Admin, but no password: it only adds protection, the same gate as
// enable-extension and block-domain.
func blockAppCmd(cfg policy.Config, cfgPath, kind, value, label string) {
	if strings.TrimSpace(value) == "" {
		fmt.Fprintln(os.Stderr, `error: application required, e.g. `+"`"+`guard block-app "C:\Games\Steam\steam.exe"`+"`")
		fmt.Fprintln(os.Stderr, "(-kind folder|store|title for a folder, a Microsoft Store app, or a window title)")
		os.Exit(2)
	}
	app, changed, err := cfg.AddApp(kind, value, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if !changed {
		fmt.Printf("%s is already blocked\n", app.Display())
		return
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	fmt.Printf("blocked: %s (%s)\n", app.Display(), app.Summary())
	if governed := governingAppBlocks(cfg, app); governed != "" {
		fmt.Printf("(scheduled by %s, so it is only enforced during those windows)\n", governed)
	}
}

// unblockAppCmd stops enforcing an application, keeping it in the list so it can
// be turned back on. That weakens protection, so it takes the password - except
// while protection is in the authorized paused state, where there is no active
// block to bypass. Mirrors unblock-domain.
func unblockAppCmd(cfg policy.Config, cfgPath, kind, value, password string) {
	if strings.TrimSpace(value) == "" {
		fmt.Fprintln(os.Stderr, "error: application required, e.g. `guard unblock-app steam.exe`")
		os.Exit(2)
	}
	if !scm.IsDisabled() {
		requirePassword(password)
	}
	app, ok := cfg.SetAppEnabled(kind, value, false)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: %q is not in the app block list\n", value)
		fmt.Fprintln(os.Stderr, "(run `guard apps` to see what is; pass -kind if it is a folder, Store app or window title)")
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	fmt.Printf("unblocked: %s can run again\n", app.Display())
}

// governingAppBlocks names the blocks that put an app on a schedule, so a user
// who blocks something and then sees it open understands why.
func governingAppBlocks(cfg policy.Config, app policy.App) string {
	var ids []string
	for _, b := range cfg.Blocks {
		if b.GovernsApp(app) {
			ids = append(ids, b.ID)
		}
	}
	return strings.Join(ids, ", ")
}

// blockedCmd is what a blocked application's launch turns into: the guard is
// registered as its debugger (see internal/policy/appblock_windows.go), so
// Windows starts this instead of the program, with the program's own command line
// appended.
//
// It must be the least demanding command there is - no config, no admin, no
// registry - because it runs in the blocked user's session on every attempt, and
// anything that can fail here turns a block into a crash the user reports as a
// bug.
func blockedCmd(args []string) {
	name := "This application"
	for _, a := range args {
		if s := strings.Trim(strings.TrimSpace(a), `"`); s != "" {
			name = baseNameOf(s)
			break
		}
	}
	notifyBlocked(name)
	// Non-zero: the launch did not do what the caller asked. Nothing reads this
	// today, but a script launching a blocked app should see a failure.
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

// agentSweep is how often the session agent re-checks the windows on screen. It
// matches the service's own sweep: a blocked window that lingers a second is
// tolerable, one that lingers ten is a block the user watched fail.
const agentSweep = 1 * time.Second

// runAgent is the session-resident half of application blocking, started by the
// service in the interactive user's session (see internal/guardsvc/agent_windows.go).
//
// It exists for one reason: a Windows service runs in session 0 and cannot see the
// user's windows, so window-title rules evaluated there would match nothing and
// silently enforce nothing. Every other rule kind is matched on the process list,
// which is session-independent, and stays with the service - which is why this
// narrows the config to title rules rather than sweeping everything. Duplicating
// the service's work here would only produce access-denied noise for processes the
// user cannot close but SYSTEM can.
//
// It holds no password and writes nothing. It exits when protection is paused,
// when an update is swapping the binaries, when the service is no longer running
// (so an orphan cannot outlive the guard that started it), and when the last title
// rule goes away - the service starts a new one if that changes.
func runAgent(cfg policy.Config, cfgPath string) {
	log.SetPrefix("agent: ")
	if !scm.AcquireSingleton(agentMutex) {
		log.Println("another agent is already running in this session; exiting")
		return
	}
	var lastErr string
	for {
		if scm.IsDisabled() || scm.IsUpdating() || !scm.IsRunning(guardsvc.ServiceName) {
			return
		}
		// Read the enforced config, not the file: an edited extension-ids.json loses
		// to the trusted copy here exactly as it does everywhere else.
		if reloaded, _, err := policy.LoadTrusted(cfgPath); err == nil {
			cfg = reloaded
		}
		active, _ := cfg.EnforcedAt(time.Now())
		titles := titleRulesOnly(active)
		if !titles.AnyApps() {
			return // nothing here needs a session any more
		}
		err := policy.SweepApps(titles)
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if msg != lastErr {
			if msg != "" {
				log.Println(msg)
			}
			lastErr = msg
		}
		time.Sleep(agentSweep)
	}
}

// agentMutex is the agent's single-instance guard. "Local\" scopes it to one
// session, which is exactly right: one agent per signed-in user, and a second
// service start cannot leave two sweeping the same desktop.
const agentMutex = `Local\ExtensionGuardAgent`

// titleRulesOnly narrows a resolved config to its window-title rules, keeping
// every rule's enabled/disabled state as the schedule left it.
func titleRulesOnly(cfg policy.Config) policy.Config {
	out := cfg
	out.Apps = nil
	for _, a := range cfg.Apps {
		if strings.EqualFold(strings.TrimSpace(a.Kind), policy.AppTitle) {
			out.Apps = append(out.Apps, a)
		}
	}
	return out
}
