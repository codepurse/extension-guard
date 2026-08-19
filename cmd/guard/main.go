// Command guard is the Extension Guard enforcement tool.
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
	extensions := flag.String("extensions", "", "comma-separated extension names to keep (used by 'select'); default keeps all")
	until := flag.String("until", "", "deadline for 'lock': a duration (72h, 7d) or a time (2026-09-01, 2026-09-01T17:00)")
	flag.Usage = usage
	flag.Parse()

	cmd := flag.Arg(0)
	if cmd == "" || cmd == "help" {
		usage()
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
	case "select":
		selectConfig(*cfgPath, *extensions)
		return
	case "commit":
		commitCmd(*cfgPath, *password)
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
		for _, k := range []policy.Kind{policy.Chrome, policy.Edge, policy.Brave, policy.Firefox} {
			fmt.Printf("  %-8s %v\n", k, detected[k])
		}
	case "blocks":
		blocksCmd(cfg)
	case "domains":
		domainsCmd(cfg)
	case "block-domain":
		blockDomainCmd(cfg, *cfgPath, flag.Arg(1))
	case "unblock-domain":
		unblockDomainCmd(cfg, *cfgPath, flag.Arg(1), *password)
	case "lock":
		lockCmd(cfg, *cfgPath, flag.Arg(1), *until)
	case "enable-extension":
		toggleExtension(cfg, *cfgPath, flag.Arg(1), true)
	case "disable-extension":
		// Disabling an extension weakens protection, so it needs the password -
		// unless protection is already in the authorized paused state, where there
		// is no active lock to bypass.
		if !scm.IsDisabled() {
			requirePassword(*password)
		}
		toggleExtension(cfg, *cfgPath, flag.Arg(1), false)
	case "set-password":
		setPassword(*password)
	case "update":
		updateCmd(cfg, *cfgPath)
	case "run", "watchdog", "install-service", "uninstall-service", "start", "stop", "disable", "enable":
		runService(cmd, cfg, *cfgPath, *password)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func runService(cmd string, cfg policy.Config, cfgPath, password string) {
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
		mustService(guardsvc.Install(cfg, absCfg), "install")
		fmt.Println("service installed, hardened, and started")
	case "uninstall-service":
		requirePassword(password)
		mustService(guardsvc.Uninstall(cfg, absCfg), "uninstall")
		_ = scm.ClearPasswordHash()
		_ = scm.ClearTrustedConfig()
		fmt.Println("service uninstalled")
	case "disable":
		requirePassword(password)
		mustService(guardsvc.Disable(cfg, absCfg), "disable")
		fmt.Println("protection disabled")
	case "enable":
		// Enabling only strengthens protection, so it needs admin but no password.
		mustService(guardsvc.Enable(cfg, absCfg), "enable")
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
func requirePassword(flagPW string) {
	hash, ok := scm.GetPasswordHash()
	if !ok {
		return
	}
	pw := flagPW
	if pw == "" {
		pw = prompt("Enter uninstall password: ")
	}
	if !auth.Verify(hash, pw) {
		fmt.Fprintln(os.Stderr, "error: incorrect password")
		os.Exit(1)
	}
}

// setPassword sets or changes the uninstall password; changing requires the
// current password.
func setPassword(flagPW string) {
	if hash, ok := scm.GetPasswordHash(); ok {
		if !auth.Verify(hash, prompt("Current password: ")) {
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
func printStatus(cfg policy.Config) {
	cfg = activeNow(cfg)
	fmt.Printf("  %-11s %-8s %-8s %-9s %s\n", "area", "target", "present", "enforced", "detail")
	for _, s := range enforce.Default().Verify(cfg) {
		fmt.Printf("  %-11s %-8s %-8v %-9v %s\n", s.Enforcer, s.Target, s.Present, s.Enforced, s.Detail)
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
		fmt.Printf("enabled: %s is now force-installed\n", name)
	} else {
		must(policy.Remove(cfg.Only(name)))
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

func usage() {
	fmt.Println(`Extension Guard

usage: guard [flags] <command>

policy commands (admin):
  apply              enforce everything the config asks for now
  verify             show what is enforced, per area and target (alias: status)
  remove             lift everything the guard enforces
  detect             list which supported browsers are installed
  select             enable only -extensions, disable the rest (used by the installer)

domain commands:
  domains            list the blocked domains and whether each is enforced now
  block-domain       <domain>  block a domain and all its subdomains (admin; no
                               password - it only adds protection)
  unblock-domain     <domain>  stop filtering a domain (password, unless paused)

schedule commands:
  blocks             list each block, whether it is enforcing now, and its lock
  lock               <id>      lock a block until -until (admin; no password -
                               a lock can be extended but never shortened)
  commit             adopt a hand-edited config file (requires the password;
                               refused outright if it would weaken a locked block)
  enable-extension   <name>   start locking an extension (adds protection; no password)
  disable-extension  <name>   stop locking an extension (password, unless already paused)

service commands (admin):
  install-service    install + harden + start the guard service (sets password)
  uninstall-service  remove the service (requires the password)
  disable            temporarily turn protection off (requires the password)
  enable             turn protection back on after a disable (no password; only strengthens)
  set-password       set or change the uninstall password
  start              start the service
  stop               stop the service
  run                run in the foreground (also used by the service manager)
  watchdog           run the watchdog loop (internal; spawned by the service)

update commands:
  check-update       report whether a newer release is available (no admin)
  update             download + install the latest release, then restart the
                     service (admin; no password - updating strengthens protection)
  version            print the build version

  help               show this help

flags:`)
	flag.PrintDefaults()
}
