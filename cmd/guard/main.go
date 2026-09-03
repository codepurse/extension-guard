// Command guard is the Ward enforcement tool.
//
//   - milestone 1: apply / verify / remove the browser force-install policy.
//   - milestone 2: run as a Windows service that re-applies the policy on tamper.
//   - milestone 3: watchdog that resurrects the service if it is stopped/killed.
//   - milestone 4: password-gated uninstall (set-password / install-service /
//     uninstall-service involve the uninstall password).
//
// The status UI and signed installer build on these commands.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/term"

	"github.com/codepurse/extension-guard/internal/activity"
	"github.com/codepurse/extension-guard/internal/auth"
	"github.com/codepurse/extension-guard/internal/buildinfo"
	"github.com/codepurse/extension-guard/internal/enforce"
	"github.com/codepurse/extension-guard/internal/guardsvc"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
	"github.com/codepurse/extension-guard/internal/updater"
	"github.com/codepurse/extension-guard/internal/usage"
)

func main() {
	cfgPath := flag.String("config", defaultConfigPath(), "path to extension-ids.json")
	password := flag.String("password", "", "uninstall password (install-service / uninstall-service / set-password)")
	extensions := flag.String("extensions", "", "comma-separated extension names: the ones to keep ('select'), or the ones a block governs ('add-block')")
	domains := flag.String("domains", "", "comma-separated domains a block governs (used by 'add-block')")
	apps := flag.String("apps", "", "comma-separated blocked apps a block governs, by value (used by 'add-block')")
	days := flag.String("days", "", "days a block's window falls on: mon,wed,fri or weekdays/weekends/daily (default every day)")
	from := flag.String("from", "", "start of a block's window, HH:MM (used by 'add-block')")
	to := flag.String("to", "", "end of a block's window, HH:MM; before the start means it runs past midnight")
	limit := flag.String("limit", "", "daily time limit for a block's apps: 45m, 1h30m, or a number of minutes (used by 'add-block')")
	until := flag.String("until", "", "deadline for 'lock': a duration (72h, 7d) or a time (2026-09-01, 2026-09-01T17:00)")
	pauseFor := flag.String("for", "", "how long 'disable' pauses protection: 30m, 2h, 1d, or a time. Omit to pause until you turn it back on")
	kind := flag.String("kind", "", "what a block-app/unblock-app argument is: exe (default), folder, store, or title")
	label := flag.String("label", "", "friendly name shown in the status window (used by 'block-app' and 'add-block')")
	level := flag.String("level", "", "how a hardened setting is set: moderate or strict for 'harden safe-search' (default strict), or a resolver id for 'harden dns-filter' (default cloudflare-family)")
	count := flag.Int("n", defaultActivityCount, "how many entries 'activity' shows")
	holdConsole := flag.Bool("hold-console", false, "wait for Enter before exiting on error; passed by the status window when it opens a console for the typing challenge")
	chars := flag.Int("chars", 0, "how long the typing challenge is, in characters (used by 'friction on'; default 256)")
	flag.Usage = printUsage
	flag.Parse()
	holdConsoleOnError = *holdConsole

	// Attribute whatever this process records to whoever is running it. The
	// service and the session agent are not people, so they are named as
	// themselves; every other command is somebody at a keyboard, and for an action
	// that weakens protection *who* did it is most of the point of writing it down.
	switch flag.Arg(0) {
	case "run", "watchdog":
		activity.Enable(activity.ActorService)
	case "agent":
		activity.Enable(activity.ActorAgent)
	default:
		activity.Enable(activity.LocalUser())
	}

	cmd := flag.Arg(0)
	if cmd == "" || cmd == "help" {
		printUsage()
		if cmd == "" {
			os.Exit(2)
		}
		return
	}

	// Handled before the config is reconciled below. version / check-update don't
	// need a config at all (and version must work even when it is missing), while
	// select and commit must see the file as written - reconciling first would
	// revert the very edit they exist to adopt.
	switch cmd {
	case "version":
		fmt.Println(buildinfo.Version)
		return
	case "check-update":
		checkUpdateCmd()
		return
	case "activity":
		// Reading the record needs neither the config nor admin, so it is handled
		// here with version and check-update rather than below.
		activityCmd(*count)
		return
	case "select":
		selectConfig(*cfgPath, *extensions)
		return
	case "commit":
		commitCmd(*cfgPath, *password)
		return
	case "blocked":
		// Windows starts this in place of a blocked application, in the blocked
		// user's session, with the application's own command line appended. It must
		// not need the config, the registry, or admin - see blockedCmd.
		blockedCmd(flag.Args()[1:])
		return
	}

	// LoadTrusted, not LoadConfig: an edited extension-ids.json loses to the
	// trusted copy here exactly as it does in the service, so status tells the
	// truth and a toggle applies on top of the enforced set rather than on top of
	// whatever someone typed into the file.
	cfg, _, err := policy.LoadTrusted(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintf(os.Stderr, "(looked for config at %s - pass -config to override)\n", *cfgPath)
		os.Exit(1)
	}

	switch cmd {
	case "apply":
		must(enforce.Default().Apply(activeNow(cfg)))
		fmt.Println("policy applied")
		printStatus(cfg)
	case "verify", "status":
		printStatus(cfg)
	case "remove":
		must(enforce.Default().Remove(cfg))
		fmt.Println("policy removed")
	case "detect":
		detected := policy.DetectBrowsers()
		for _, k := range policy.AllKinds() {
			fmt.Printf("  %-8s %v\n", k, detected[k])
		}
	case "browsers":
		browsersCmd(cfg)
	case "blocks":
		blocksCmd(cfg)
	case "limits":
		limitsCmd(cfg)
	case "usage":
		usageCmd(cfg, flag.Arg(1))
	case "domains":
		domainsCmd(cfg)
	case "block-domain":
		blockDomainCmd(cfg, *cfgPath, flag.Arg(1))
	case "unblock-domain":
		unblockDomainCmd(cfg, *cfgPath, flag.Arg(1), *password)
	case "allowed":
		allowedCmd(cfg)
	case "allow-only":
		allowOnlyCmd(cfg, *cfgPath, flag.Arg(1), *password)
	case "allow":
		allowCmd(cfg, *cfgPath, flag.Arg(1), *password)
	case "unallow":
		unallowCmd(cfg, *cfgPath, flag.Arg(1))
	case "apps":
		appsCmd(cfg)
	case "categories":
		categoriesCmd(cfg, flag.Arg(1))
	case "block-category":
		blockCategoryCmd(cfg, *cfgPath, flag.Arg(1))
	case "hardening":
		hardeningCmd(cfg)
	case "harden":
		hardenCmd(cfg, *cfgPath, flag.Arg(1), *level, *password)
	case "unharden":
		unhardenCmd(cfg, *cfgPath, flag.Arg(1), *password)
	case "agent":
		// Internal: the service starts this in the signed-in user's session, because
		// a service cannot see that session's windows. See runAgent.
		runAgent(cfg, *cfgPath)
	case "block-app":
		blockAppCmd(cfg, *cfgPath, *kind, flag.Arg(1), *label)
	case "unblock-app":
		unblockAppCmd(cfg, *cfgPath, *kind, flag.Arg(1), *password)
	case "add-block":
		addBlockCmd(cfg, *cfgPath, flag.Arg(1), blockSpec{
			label:      *label,
			days:       *days,
			from:       *from,
			to:         *to,
			limit:      *limit,
			extensions: *extensions,
			domains:    *domains,
			apps:       *apps,
		}, *password)
	case "remove-block":
		removeBlockCmd(cfg, *cfgPath, flag.Arg(1), *password)
	case "lock":
		lockCmd(cfg, *cfgPath, flag.Arg(1), *until)
	case "enable-extension":
		toggleExtension(cfg, *cfgPath, flag.Arg(1), true)
	case "disable-extension":
		// Disabling an extension weakens protection, so it needs the password -
		// unless protection is already in the authorized paused state, where there
		// is no active lock to bypass.
		if !scm.IsPaused() {
			requirePassword(*password, "turning an extension off")
		}
		toggleExtension(cfg, *cfgPath, flag.Arg(1), false)
	case "set-password":
		setPassword(*password)
	case "friction":
		frictionCmd(flag.Arg(1), *chars, *password)
	case "update":
		updateCmd(cfg, *cfgPath)
	case "run", "watchdog", "install-service", "uninstall-service", "start", "stop", "disable", "enable":
		runService(cmd, cfg, *cfgPath, *password, *pauseFor)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func runService(cmd string, cfg policy.Config, cfgPath, password, pauseFor string) {
	absCfg, err := filepath.Abs(cfgPath)
	if err != nil {
		absCfg = cfgPath
	}
	svc, err := guardsvc.New(cfg, absCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	switch cmd {
	case "run":
		if err := svc.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "service run error: %v\n", err)
			os.Exit(1)
		}
	case "watchdog":
		if err := guardsvc.RunWatchdog(cfg, absCfg); err != nil {
			fmt.Fprintf(os.Stderr, "watchdog error: %v\n", err)
			os.Exit(1)
		}
	case "install-service":
		ensurePasswordSet(password)
		// Elevated, so this may create the activity log; the service would do it
		// moments later anyway, but doing it here means the install's own entry
		// lands in the record rather than being dropped in the gap. Only privileged
		// code may create it - see internal/activity.
		_ = activity.Provision()
		// The ledger is created here for the same reason: it must be owned by
		// something privileged, and the service would do it moments later anyway.
		// See internal/usage.
		_ = usage.Provision()
		mustService(guardsvc.Install(cfg, absCfg), "install")
		activity.Record(activity.Event{Kind: activity.ProtectionInstalled, Target: buildinfo.Version})
		fmt.Println("service installed, hardened, and started")
	case "uninstall-service":
		requirePassword(password, "uninstalling protection")
		mustService(guardsvc.Uninstall(cfg, absCfg), "uninstall")
		_ = scm.ClearPasswordHash()
		_ = scm.ClearTrustedConfig()
		// The log itself is deliberately left where it is. It records that
		// protection was removed, and an accountability record an uninstall erases
		// is not one.
		activity.Record(activity.Event{Kind: activity.ProtectionRemoved})
		fmt.Println("service uninstalled")
	case "disable":
		// A live lock refuses a pause, because a pause lifts everything the lock was
		// holding - see policy.CheckPausable for why this is not the same question
		// CheckLockedBlocks answers, and why uninstalling stays allowed.
		//
		// Checked before the password is asked for, the way add-block and commit do
		// it: being prompted for a password and *then* told no wastes the one step
		// that costs the user something.
		if err := policy.CheckPausable(cfg, time.Now()); err != nil {
			activity.Record(activity.Event{Kind: activity.PauseRefused, Detail: err.Error()})
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			fmt.Fprintln(os.Stderr, "(nothing was changed; uninstalling still works, and takes the blocks with it)")
			os.Exit(1)
		}
		// Parsed before the password too, so a mistyped duration is not something
		// you find out about after authenticating.
		deadline, err := pauseDeadline(pauseFor, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		requirePassword(password, "pausing protection")
		mustService(guardsvc.Pause(cfg, absCfg, deadline), "pause")
		// Lift here rather than waiting for the service to come round to it. The
		// service would do it within thirty seconds, but the user has just been told
		// protection is off, and half a minute of it still being on reads as the
		// command not having worked.
		must(enforce.Default().Remove(cfg))
		activity.Record(activity.Event{Kind: activity.ProtectionPaused, Detail: pauseDetail(deadline)})
		fmt.Printf("protection paused %s\n", pauseDetail(deadline))
		fmt.Println("(the guard stays installed and running, so it can turn itself back on)")
	case "enable":
		// Enabling only strengthens protection, so it needs admin but no password.
		_ = activity.Provision()
		_ = usage.Provision()
		mustService(guardsvc.Resume(cfg, absCfg), "resume")
		must(enforce.Default().Apply(activeNow(cfg)))
		activity.Record(activity.Event{Kind: activity.ProtectionResumed})
		fmt.Println("protection enabled")
	case "start":
		mustService(service.Control(svc, "start"), "start")
		fmt.Println("service started")
	case "stop":
		mustService(service.Control(svc, "stop"), "stop")
		fmt.Println("service stopped")
	}
}

// ensurePasswordSet makes sure an uninstall password exists before install. A
// password already stored (e.g. a watchdog re-install) is kept; otherwise it is
// taken from -password or prompted, validated, hashed, and stored.
func ensurePasswordSet(flagPW string) {
	if _, ok := scm.GetPasswordHash(); ok {
		return
	}
	pw := flagPW
	if pw == "" {
		pw = prompt("Set uninstall password: ")
	}
	if len(pw) < auth.MinLength {
		fmt.Fprintf(os.Stderr, "error: password must be at least %d characters\n", auth.MinLength)
		os.Exit(1)
	}
	hash, err := auth.Hash(pw)
	must(err)
	mustService(scm.SetPasswordHash(hash), "store password")
}

// requirePassword aborts unless the supplied password matches the stored hash.
// If no password is set, the action is allowed.
//
// what names the action being attempted, for the activity log. A wrong password
// is recorded because it is the clearest signal there is that somebody tried to
// get around the gate - and unlike the action itself, an attempt that fails
// leaves no other trace at all.
func requirePassword(flagPW, what string) {
	if hash, ok := scm.GetPasswordHash(); ok {
		pw := flagPW
		if pw == "" {
			pw = prompt("Enter uninstall password: ")
		}
		if !auth.Verify(hash, pw) {
			activity.Record(activity.Event{Kind: activity.PasswordFailed, Target: what})
			fmt.Fprintln(os.Stderr, "error: incorrect password")
			holdConsole()
			os.Exit(1)
		}
	}
	// Then the typing challenge, if one is configured. The two gates answer
	// different questions - the password whether you are allowed to do this, the
	// challenge whether you still mean to - and they are independent settings, so
	// a machine may have either, both or neither.
	//
	// The password goes first because it is the cheap one. Asking for minutes of
	// typing and then refusing the password would spend the expensive gate on
	// somebody who was never going to get through, and a gate that punishes the
	// wrong person is the one the right person asks to have removed.
	requireChallenge(what)
}

// setPassword sets or changes the uninstall password; changing requires the
// current password.
func setPassword(flagPW string) {
	if hash, ok := scm.GetPasswordHash(); ok {
		if !auth.Verify(hash, prompt("Current password: ")) {
			activity.Record(activity.Event{Kind: activity.PasswordFailed, Target: "changing the password"})
			fmt.Fprintln(os.Stderr, "error: incorrect current password")
			os.Exit(1)
		}
	}
	pw := flagPW
	if pw == "" {
		pw = prompt("New password: ")
	}
	if len(pw) < auth.MinLength {
		fmt.Fprintf(os.Stderr, "error: password must be at least %d characters\n", auth.MinLength)
		os.Exit(1)
	}
	hash, err := auth.Hash(pw)
	must(err)
	mustService(scm.SetPasswordHash(hash), "store password")
	activity.Record(activity.Event{Kind: activity.PasswordChanged})
	fmt.Println("password updated")
}

// prompt reads one line from the terminal without echoing it.
func prompt(label string) string {
	fmt.Print(label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
		os.Exit(1)
	}
	return strings.TrimSpace(string(b))
}

// activeNow resolves the schedule the same way the service does, printing any
// problem that forced the fail-closed fallback so the operator sees it.
func activeNow(cfg policy.Config) policy.Config {
	active, err := cfg.EnforcedAt(time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		fmt.Fprintln(os.Stderr, "(the schedule is being ignored; every enabled extension stays enforced)")
	}
	return active
}

// printStatus lists what every enforcer reports. The columns are the general
// ones rather than browser-specific: "target" is a browser today and an
// executable once app blocking lands, and "present" means the target exists on
// this machine.
//
// It reports against the schedule-resolved config, so "enforced" means "matches
// what should be locked at this moment" - outside a block's window its
// extensions are supposed to be absent, and showing that as a failure would be
// wrong.
//
// The browser warning underneath is not a row in the table on purpose. The table
// reports what the guard enforces, and an unmanaged browser is the opposite of
// that - see internal/policy/browsers.go. But a table saying every browser is
// locked, printed on a machine where Opera is filtering nothing, is a true
// statement doing the work of a false one, so it does not get to be the last word
// on the screen.
func printStatus(cfg policy.Config) {
	active := activeNow(cfg)
	fmt.Printf("  %-11s %-8s %-8s %-9s %s\n", "area", "target", "present", "enforced", "detail")
	for _, s := range enforce.Default().Verify(active) {
		fmt.Printf("  %-11s %-8s %-8v %-9v %s\n", s.Enforcer, s.Target, s.Present, s.Enforced, s.Detail)
	}
	// The whole config, not the resolved one: this warns about browsers nothing on
	// the block list covers, and a browser blocked on a schedule is covered even
	// while its window is shut. See policy.UnblockedBrowsers.
	if w := unmanagedBrowserWarning(cfg); w != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", w)
	}
	// The same reasoning one step inside the browsers the guard *does* manage: an
	// extension it force-installs does not run in a private window, so a table of
	// locked browsers over an available Ctrl+Shift+N is the same true statement
	// doing the same false work. See policy.Config.PrivateBrowsingOpen.
	if w := privateBrowsingWarning(cfg); w != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", w)
	}
}

// selectConfig marks the chosen extensions enabled and the rest disabled,
// keeping every extension in the file (the catalog). The installer calls this
// after the user picks components; the service, watchdog, and status window all
// read this file, and disabled entries stay listed so they can be turned on
// later from the status window.
//
// It reads the file directly rather than going through the trusted copy the rest
// of main.go works from, and runs before main reconciles the two. This is the one
// path where the file legitimately wins: the installer has just laid down a
// freshly shipped extension-ids.json, and an upgrade that widens the catalog or
// corrects an extension ID (as 29ce5c8 did) must be adopted, not reverted as
// tamper. Every other authorized change is an incremental edit to what the
// trusted copy already says.
func selectConfig(outPath, extensions string) {
	cfg, err := policy.LoadConfig(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	cfg.EnableOnly(splitAndTrim(extensions))
	if !cfg.AnyEnabled() {
		fmt.Fprintln(os.Stderr, "error: -extensions matched no known extension; refusing to disable them all")
		os.Exit(1)
	}
	writeConfig(cfg, outPath)
	var enabled []string
	for _, e := range cfg.Extensions {
		if !e.Disabled {
			enabled = append(enabled, e.Name)
		}
	}
	fmt.Printf("config now enforces: %s\n", strings.Join(enabled, ", "))
}

// toggleExtension enables or disables one extension by name, rewrites the config
// (the source of truth the service re-reads each cycle), and applies or lifts
// just that extension's browser lock.
func toggleExtension(cfg policy.Config, cfgPath, name string, enable bool) {
	if strings.TrimSpace(name) == "" {
		fmt.Fprintln(os.Stderr, "error: name required, e.g. `guard enable-extension sieve`")
		os.Exit(2)
	}
	if !cfg.SetEnabled(name, enable) {
		fmt.Fprintf(os.Stderr, "error: no extension named %q in the config\n", name)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	if enable {
		must(enforce.Default().Apply(activeNow(cfg)))
		activity.Record(activity.Event{Kind: activity.ExtensionEnabled, Target: name})
		fmt.Printf("enabled: %s is now force-installed\n", name)
	} else {
		must(policy.Remove(cfg.Only(name)))
		activity.Record(activity.Event{Kind: activity.ExtensionDisabled, Target: name})
		fmt.Printf("disabled: %s is no longer locked\n", name)
	}
	printStatus(cfg)
}

// writeConfig persists an authorized config change: it records the config as the
// trusted copy and then writes the file. Nothing else may write the config file -
// a plain file write would be reverted by the service on its next cycle, which is
// exactly the protection that makes hand-editing extension-ids.json ineffective.
func writeConfig(cfg policy.Config, outPath string) {
	must(policy.Commit(cfg, outPath))
}

// splitAndTrim turns "a, b ,c" into ["a","b","c"], dropping blanks.
func splitAndTrim(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, "(writing/removing policy requires an elevated Administrator shell)")
		os.Exit(1)
	}
}

func mustService(err error, action string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: service %s failed: %v\n", action, err)
		fmt.Fprintln(os.Stderr, "(service install/uninstall requires an elevated Administrator shell)")
		os.Exit(1)
	}
}

// defaultConfigPath finds extension-ids.json: first next to the binary (where
// the installer places a copy), then by walking up from the working directory
// (so `go run ./cmd/guard` works from anywhere in the repo).
func defaultConfigPath() string {
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), "extension-ids.json"); fileExists(p) {
			return p
		}
	}
	if dir, err := os.Getwd(); err == nil {
		for i := 0; i < 6; i++ {
			if p := filepath.Join(dir, "extension-ids.json"); fileExists(p) {
				return p
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "extension-ids.json"
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// checkUpdateCmd reports whether a newer release is available on GitHub. It is
// read-only and needs no admin rights, so the status window and users can run it
// freely.
func checkUpdateCmd() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rel, err := updater.CheckLatest(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if !rel.Newer(buildinfo.Version) {
		fmt.Printf("up to date (running %s, latest %s)\n", buildinfo.Version, rel.Version)
		return
	}
	fmt.Printf("update available: %s (running %s)\n", rel.Version, buildinfo.Version)
	if strings.TrimSpace(rel.Notes) != "" {
		fmt.Printf("\n%s\n", rel.Notes)
	}
}

// updateCmd downloads the latest release (if newer) and swaps its binaries in,
// restarting the service so the new image loads. It needs admin rights (it
// writes into the install dir and controls the service) but NOT the uninstall
// password: like enabling an extension, updating only strengthens protection, so
// it is gated on admin/UAC alone.
//
// The swap is cooperative with the self-healing loop: set the "updating"
// sentinel so the watchdog stands down, give it a moment to observe that, stop
// the service, rename the old binaries aside and the new ones in, clear the
// sentinel, and start the service (which spawns a fresh watchdog from the new
// binary). The sentinel is cleared on every exit path so a failure never leaves
// the guard un-watched.
func updateCmd(cfg policy.Config, cfgPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	rel, err := updater.CheckLatest(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: check for update: %v\n", err)
		os.Exit(1)
	}
	if !rel.Newer(buildinfo.Version) {
		fmt.Printf("already up to date (running %s, latest %s)\n", buildinfo.Version, rel.Version)
		return
	}
	fmt.Printf("updating %s -> %s\n", buildinfo.Version, rel.Version)

	exe, err := os.Executable()
	must(err)
	dir := filepath.Dir(exe)

	staged, err := rel.Stage(ctx, dir, updateAssetNames()...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	absCfg, err := filepath.Abs(cfgPath)
	if err != nil {
		absCfg = cfgPath
	}
	svc, err := guardsvc.New(cfg, absCfg)
	must(err)

	// Pause the watchdog, then let it observe the sentinel before we stop the
	// service (mirrors the uninstall teardown wait, which closes the same race).
	_ = scm.SetUpdating(true)
	running := scm.IsRunning(guardsvc.ServiceName)
	if running {
		time.Sleep(watchdogStandDownWait)
		if err := service.Control(svc, "stop"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: stop service: %v\n", err)
		}
		waitForStop(guardsvc.ServiceName, 15*time.Second)
	}

	if err := updater.SwapFiles(dir, staged); err != nil {
		_ = scm.SetUpdating(false)
		if running {
			_ = service.Control(svc, "start") // best-effort: bring the old one back up
		}
		fmt.Fprintf(os.Stderr, "error: swap binaries: %v\n", err)
		os.Exit(1)
	}

	// Clear the sentinel before (re)starting so the fresh service arms its
	// watchdog from the new binary.
	_ = scm.SetUpdating(false)
	if running {
		if err := service.Control(svc, "start"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: start service: %v\n", err)
		}
	}
	activity.Record(activity.Event{
		Kind:   activity.UpdateApplied,
		Target: rel.Version,
		Detail: "from " + buildinfo.Version,
	})
	fmt.Printf("updated to %s. Restart the status window to load the new UI.\n", rel.Version)
}

// updateAssetNames is the set of binaries an update replaces, matching the
// release asset (and manifest) names for this platform.
func updateAssetNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"guard.exe", "extension-guard-status.exe"}
	}
	return []string{"guard", "extension-guard-status"}
}

// watchdogStandDownWait is how long to wait after setting the updating sentinel
// for the watchdog to notice and exit before we stop the service.
const watchdogStandDownWait = 7 * time.Second

// waitForStop blocks until the named service is no longer running, or timeout.
func waitForStop(name string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !scm.IsRunning(name) {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// printUsage is the help text. It is not called "usage" because that name now
// belongs to the package that counts how long a limited block has been used.
func printUsage() {
	fmt.Println(`Ward

usage: guard [flags] <command>

policy commands (admin):
  apply              enforce everything the config asks for now
  verify             show what is enforced, per area and target (alias: status)
  remove             lift everything the guard enforces
  detect             list which supported browsers are installed
  select             enable only -extensions, disable the rest (used by the installer)

browser commands:
  browsers           list every browser on this machine and what the guard can do
                     about each: filtered (it reads the guard's policy), blocked,
                     or reachable - a browser the guard neither filters nor blocks,
                     through which every blocked site is one click away. Needs no
                     admin and no password, like 'activity'

browser setting commands:
  hardening          list the pinned browser settings, where each reaches, and
                     whether private browsing is still open - which is the hole
                     that makes a locked extension optional, since one cannot be
                     force-installed into a private or guest window. Needs no
                     admin and no password, like 'activity'
  harden             <setting>  pin a browser setting (admin; no password - it
                                only adds protection):
                                  private-browsing  no private or guest windows
                                  safe-search       SafeSearch + YouTube
                                                    restricted mode; -level takes
                                                    moderate or strict (default)
                                  dns-filter        resolve DNS through Cloudflare
                                                    for Families, which filters
                                                    malware and adult content.
                                                    Pinned closed: if it cannot be
                                                    reached, pages do not load
  unharden           <setting>  hand a setting back (password, unless paused)

domain commands:
  domains            list the blocked domains and whether each is enforced now
  block-domain       <domain>  block a domain and all its subdomains (admin; no
                               password - it only adds protection)
  unblock-domain     <domain>  stop filtering a domain (password, unless paused)
  allowed            list the allowed-sites-only mode, its timetable, and the
                     sites it lets through
  allow-only         on|off    block every site except the allowlist. Turning it
                               on only strengthens (admin, no password); turning
                               it off unblocks the whole web (password)
  allow              <domain>  let a site through the mode - the one kind of
                               "add" here that weakens protection, so it takes
                               the password while the mode is on
  unallow            <domain>  stop letting a site through (admin; no password -
                               it only closes something)

application commands:
  usage              [days]    how long each blocked application actually ran -
                               today and over the last 7 days, or the number of
                               days given. Needs no admin and no password, like
                               'activity' and 'limits'
  apps               list the blocked applications and whether each is enforced now
  block-app          <app>     keep an application closed (admin; no password -
                               it only adds protection). -kind picks what <app> is:
                                 exe    (default) a path or a name: steam.exe
                                 folder every .exe in a folder
                                 store  a Microsoft Store app, by package family
                                 title  any window whose title contains the text
                               -label sets the name the status window shows
  unblock-app        <app>     let an application run again (password, unless
                               paused); pass the same -kind it was added with
  categories         [id]      list the built-in categories and which are
                               blocked. Name one to see everything it covers,
                               and which of it is blocked already - worth doing
                               before block-category, since a category is
                               agreed to all at once
  block-category     <id>      block a whole category at once - every application
                               and site it names, governed by one always-on block
                               under the category's id (admin; no password - like
                               block-app it only adds protection). Run it again
                               after an update to take whatever the category has
                               gained. To lift one, remove-block its id and
                               unblock-app what you want back: those take the
                               password, because those are what weakens

schedule commands:
  blocks             list each block, whether it is enforcing now, its daily
                     limit, and its lock
  limits             show each daily time limit and how much of today is left
                     (no admin and no password - the person a limit applies to
                     is meant to be able to see where they stand)
  add-block          [id]      create a block. -label names it (the id is derived
                               from the label when you omit it), -extensions /
                               -domains / -apps say what it governs (naming none
                               governs everything), and -days -from -to give it a
                               window. -limit gives it a daily time limit
                               (45m, 1h30m, or a number of minutes), which may
                               only cover applications - the guard measures use
                               by watching processes, and a browser never
                               reports back. With a window or a limit it needs
                               the password: both enforce things only sometimes,
                               which is weaker than around the clock. With
                               neither it is always on, so it is free - that is
                               the shape to create and then lock.
  remove-block       <id>      delete a block, returning what it governed to
                               around-the-clock enforcement (password; refused
                               while the block is locked)
  lock               <id>      lock a block until -until (admin; no password -
                               a lock can be extended but never shortened)
  commit             adopt a hand-edited config file (requires the password;
                               refused outright if it would weaken a locked block)
  enable-extension   <name>   start locking an extension (adds protection; no password)
  disable-extension  <name>   stop locking an extension (password, unless already paused)

service commands (admin):
  install-service    install + harden + start the guard service (sets password)
  uninstall-service  remove the service (requires the password)
  disable            pause protection (requires the password). -for says how long
                     - 30m, 2h, 1d, or a time - and the guard turns protection
                     back on by itself when it is up. Omit -for to pause until
                     you turn it back on. The service stays installed and running
                     either way, so a pause can end on its own; it is refused
                     outright while any block is locked
  enable             end a pause (no password; only strengthens)
  set-password       set or change the uninstall password
  friction           show the typing challenge; 'friction on' turns it on (-chars
                     sets the length, 256 by default), 'friction off' turns it off.
                     While it is on, every action that weakens protection asks for
                     the password and then for a string of random characters typed
                     out by hand - pasting is refused. Turning it on or lengthening
                     it is free; shortening or turning it off goes through the
                     challenge itself, at the length in force
  start              start the service
  stop               stop the service
  run                run in the foreground (also used by the service manager)
  watchdog           run the watchdog loop (internal; spawned by the service)
  blocked            report that a launch was blocked (internal; Windows starts
                     this in place of a blocked application)
  agent              sweep window-title rules in the signed-in user's session
                     (internal; spawned by the service, which cannot see them)

record commands:
  activity           show what the guard did and what was done to it, newest
                     first: refused launches, pauses, rules added and lifted,
                     tamper it corrected, wrong passwords. No admin and no
                     password - the record is meant to be readable by everyone
                     it is about. Show more with the flag before the command,
                     as everywhere else here: "guard -n 200 activity".

update commands:
  check-update       report whether a newer release is available (no admin)
  update             download + install the latest release, then restart the
                     service (admin; no password - updating strengthens protection)
  version            print the build version

  help               show this help

flags:`)
	flag.PrintDefaults()
}

// pauseDeadline turns the -for flag into a moment to resume at. An empty flag
// means an indefinite pause, which is the zero time.
//
// It accepts what -until accepts, so "30m", "1d" and "2026-09-01T17:00" all mean
// what they look like and there is one place that decides what a deadline is.
func pauseDeadline(spec string, now time.Time) (time.Time, error) {
	if strings.TrimSpace(spec) == "" {
		return time.Time{}, nil
	}
	at, err := parseUntil(spec, now)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot read -for %q: %w", spec, err)
	}
	return at, nil
}

// pauseDetail describes a pause the way both the log and the console should say
// it, so the record and what the user was told match word for word.
func pauseDetail(deadline time.Time) string {
	if deadline.IsZero() {
		return "until it is turned back on"
	}
	return "until " + deadline.Local().Format(time.RFC1123)
}
