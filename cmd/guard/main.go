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
)

func main() {
	cfgPath := flag.String("config", defaultConfigPath(), "path to extension-ids.json")
	password := flag.String("password", "", "uninstall password (install-service / uninstall-service / set-password)")
	extensions := flag.String("extensions", "", "comma-separated extension names: the ones to keep ('select'), or the ones a block governs ('add-block')")
	pauseFor := flag.String("for", "", "how long 'disable' pauses protection: 30m, 2h, 1d, or a time. Omit to pause until you turn it back on")
	count := flag.Int("n", defaultActivityCount, "how many entries 'activity' shows")
	flag.Usage = printUsage
	flag.Parse()

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
	case "blocked":
		// Windows starts this in place of a blocked browser, in that user's session,
		// with the browser's own command line appended. It must not need the config,
		// the registry, or admin - see blockedCmd.
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
		must(enforce.Default().Apply(cfg))
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
	case "block-browsers":
		blockBrowsersCmd(cfg, *cfgPath, true, *password)
	case "unblock-browsers":
		blockBrowsersCmd(cfg, *cfgPath, false, *password)
	case "hardening":
		hardeningCmd(cfg)
	case "harden":
		hardenCmd(cfg, *cfgPath, flag.Arg(1), *password)
	case "unharden":
		unhardenCmd(cfg, *cfgPath, flag.Arg(1), *password)
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
		mustService(guardsvc.Install(cfg, absCfg), "install")
		activity.Record(activity.Event{Kind: activity.ProtectionInstalled, Target: buildinfo.Version})
		fmt.Println("service installed, hardened, and started")
	case "uninstall-service":
		requirePassword(password, "uninstalling protection")
		mustService(guardsvc.Uninstall(cfg, absCfg), "uninstall")
		_ = scm.ClearPasswordHash()
		_ = scm.ClearTrustedConfig()
		// Uninstall has just removed the policy, so the note of what was written
		// describes nothing. Keeping it would leave a later install pruning ids it
		// never wrote, on a machine whose forcelist may have moved on since.
		_ = scm.ClearWrittenTargets()
		// The log itself is deliberately left where it is. It records that
		// protection was removed, and an accountability record an uninstall erases
		// is not one.
		activity.Record(activity.Event{Kind: activity.ProtectionRemoved})
		fmt.Println("service uninstalled")
	case "disable":
		// A live lock refuses a pause, because a pause lifts everything the lock was
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
		mustService(guardsvc.Resume(cfg, absCfg), "resume")
		must(enforce.Default().Apply(cfg))
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
	hash, ok := scm.GetPasswordHash()
	if !ok {
		return
	}
	pw := flagPW
	if pw == "" {
		pw = prompt("Enter uninstall password: ")
	}
	if !auth.Verify(hash, pw) {
		activity.Record(activity.Event{Kind: activity.PasswordFailed, Target: what})
		fmt.Fprintln(os.Stderr, "error: incorrect password")
		os.Exit(1)
	}
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
	active := cfg
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
		must(enforce.Default().Apply(cfg))
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
	fmt.Print(`Extension Guard

usage: guard [flags] <command>

The guard force-installs browser extensions and stops them being removed. Two
settings decide whether that lock actually holds, and both are here.

status:
  verify             what is enforced, per browser (alias: status)
  browsers           every browser on this machine and what the guard can do
                     about each: managed, blocked, or reachable - a browser it
                     neither manages nor blocks carries none of the locked
                     extensions. Needs no admin and no password
  hardening          the pinned browser settings, and whether private browsing
                     is still open - which is the hole that makes a locked
                     extension optional, since one cannot be force-installed
                     into a private or guest window
  activity           the local record of what the guard did, and what was done
                     to the guard
  version            the running build

extensions (admin):
  apply              enforce what the config asks for now
  remove             lift everything the guard enforces
  detect             which supported browsers are installed
  select             enable only -extensions, disable the rest (the installer
                     uses this)
  enable-extension   <name>  lock it back into every browser that can carry it
  disable-extension  <name>  stop force-installing it (password)

closing the two holes (admin):
  block-browsers     block the browsers the guard cannot reach
  unblock-browsers   let them run again (password)
  harden             <setting>  pin a browser setting:
                                  private-browsing    no private or guest windows
                                  private-extensions  Edge only: InPrivate refuses
                                                      to navigate until the locked
                                                      extensions are allowed there
  unharden           <setting>  hand a setting back (password)

the service:
  install-service    install, harden and start it (sets the password)
  uninstall-service  remove it and lift everything (password)
  start / stop       start or stop it
  disable            pause protection, optionally -for 30m, 2h, 1d (password)
  enable             end a pause
  set-password       set or change the password
  update             install a newer release if there is one
  check-update       ask whether there is one

flags:
  -config <path>     extension-ids.json to use
  -password <pw>     supply the password rather than being asked
  -extensions <a,b>  which extensions 'select' keeps
  -for <duration>    how long 'disable' pauses for
  -n <count>         how many entries 'activity' shows
`)
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
