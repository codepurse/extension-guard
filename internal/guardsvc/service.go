// Package guardsvc hosts Ward as a long-running service and its
// watchdog companion. The service applies the force-install policy on start,
// re-applies it on registry tamper (via the watcher) and on a backstop timer,
// and spawns a watchdog process. The watchdog re-asserts service recovery,
// restarts the service if it is stopped or disabled, and re-installs it if the
// service entry is deleted - so stopping or killing the guard does not stick.
package guardsvc

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/service"

	"github.com/codepurse/extension-guard/internal/activity"
	"github.com/codepurse/extension-guard/internal/buildinfo"
	"github.com/codepurse/extension-guard/internal/enforce"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
	"github.com/codepurse/extension-guard/internal/updater"
	"github.com/codepurse/extension-guard/internal/watcher"
)

const (
	// ServiceName is the SCM service name; the watchdog references it too.
	ServiceName = "ExtensionGuard"

	backstop = 30 * time.Second
	// pauseTick is how often the service checks whether a pause has run out. It
	// compares a stored deadline and does no registry work, so it can run far more
	// often than the backstop - and being late to *resume* is a gap somebody could
	// walk through.
	pauseTick = 5 * time.Second
	// reasonRegistryChange is the reapply reason the registry watcher passes. It is
	// named because recordPolicyTamper keys off it, and a typo in either place
	// would silently stop tamper being recorded.
	reasonRegistryChange = "registry change"
	// tamperThrottle is how often the same kind of tamper is written to the
	// activity log. Something rewriting a policy key in a loop should show up as
	// happening, not as a thousand identical lines.
	tamperThrottle = 1 * time.Minute

	watchdogInterval = 5 * time.Second
	watchdogRespawn  = 2 * time.Second
	watchdogMutex    = `Local\ExtensionGuardWatchdog`

	// updateCheckInterval is how often the service polls GitHub for a newer
	// release; updateStartupDelay staggers the first check so it doesn't race
	// service startup. updateCheckTimeout bounds a single check.
	updateCheckInterval = 6 * time.Hour
	updateStartupDelay  = 2 * time.Minute
	updateCheckTimeout  = 30 * time.Second
)

type program struct {
	cfg         policy.Config
	configPath  string
	logger      service.Logger
	quit        chan struct{}
	interactive bool

	w   *watcher.Watcher
	mu  sync.Mutex
	dog *exec.Cmd

	// applyMu serializes reapply and guards cfg. Two goroutines reach it - the
	// main loop and the registry watcher's callback - and two concurrent applies
	// would race each other writing the same policy keys.
	applyMu sync.Mutex
	// enforcers is the set the service drives, and pausedAt reads the pause
	// state. Both are fields rather than direct calls to enforce.Default and
	// scm.Paused so the loop can be tested at all: those two reach the real
	// registry and the real browser policy, which is not something a test may
	// touch, and between them they decide everything reapply does.
	enforcers enforce.Set
	pausedAt  func() scm.PauseState
	// paused latches whether the last cycle found protection paused, so the
	// transitions either side of a pause happen exactly once: enforcement is lifted
	// when one starts, and re-applied when one ends. Without it the service would
	// rewrite the same registry keys every thirty seconds for the whole pause.
	paused bool
}

// New builds the service. configPath is embedded into the service's launch
// arguments so the Service Control Manager passes it back to `guard run` - a
// service's working directory is System32, so the config can't be located by
// walking up the tree. Flags precede the subcommand because Go's flag parser
// stops at the first non-flag argument.
func New(cfg policy.Config, configPath string) (service.Service, error) {
	prg := &program{
		cfg:        cfg,
		configPath: configPath,
		quit:       make(chan struct{}),
		enforcers:  enforce.Default(),
		pausedAt:   scm.Paused,
	}
	conf := &service.Config{
		Name:        ServiceName,
		DisplayName: "Ward",
		Description: "Blocks the configured apps, sites and browser extensions, enforces schedules and daily limits, and re-applies the policy if it is tampered with.",
		Arguments:   []string{"-config", configPath, "run"},
		// systemd: auto-restart the daemon if it dies. Ignored on Windows, where
		// SCM recovery actions are configured separately by scm.Harden.
		Option: service.KeyValue{"Restart": "always"},
	}
	s, err := service.New(prg, conf)
	if err != nil {
		return nil, err
	}
	logger, err := s.Logger(nil)
	if err != nil {
		return nil, err
	}
	prg.logger = logger
	prg.interactive = service.Interactive()
	return s, nil
}

// The install path reaches the service control manager and the SYSTEM-owned
// state store, neither of which a test may touch, so both go through vars the
// tests substitute - the same seam policy/trust.go uses for the trusted store.
// replaceWait is one too, because the real value is a sleep no test should sit
// through.
var (
	serviceExists  = scm.Exists
	serviceRunning = scm.IsRunning
	serviceHarden  = scm.Harden
	setDisabled    = scm.SetDisabled
	controlService = service.Control
	// defaultEnforcers is the set Uninstall lifts protection with. The service
	// itself carries its own (program.enforcers); this is for the package-level
	// teardown, and it is a var for the same reason: the real one writes browser
	// policy, which a test may not do.
	defaultEnforcers = enforce.Default
	replaceWait      = watchdogInterval + 2*time.Second
	// stopWait is how long a replacement waits for the outgoing service to
	// actually stop, and createWait how long the incoming one waits for its name
	// to come free. Both are polled at pollInterval.
	stopWait     = 20 * time.Second
	createWait   = 20 * time.Second
	pollInterval = 250 * time.Millisecond
)

// Install registers the service, hardens it (recovery + Automatic start),
// clears the disabled sentinel, and starts it.
//
// A registration that already exists is replaced rather than refused. Refusing
// was a real hole rather than a strict-correctness nicety: `service.Control(s,
// "install")` fails with "already exists", which is precisely what an installer
// re-run or an upgrade hits, and the installer's post-install step could only
// report an error the person running it had no way to act on. Setup then went on
// to declare success - leaving the new binaries on disk with the *old* service
// still enforcing from wherever it happened to be registered, which is the one
// outcome that looks installed and is not.
func Install(cfg policy.Config, configPath string) error {
	if serviceExists(ServiceName) {
		if err := replaceRegistration(cfg, configPath); err != nil {
			// Put the sentinel back the way an untouched machine has it. The old
			// service is very likely still registered and running, and a failed
			// install must not be the thing that stops the watchdog guarding it.
			_ = setDisabled(false)
			return fmt.Errorf("replace the existing service registration: %w", err)
		}
	}
	if err := setDisabled(false); err != nil {
		return err
	}
	return install(cfg, configPath)
}

// replaceRegistration removes the service already registered here so Install can
// register this binary and this config path in its place.
//
// The sentinel-then-wait is the teardown Uninstall performs, for the reason
// given there: a live watchdog re-installs the service within watchdogInterval
// of noticing it gone. Without the pause it wins the race, and the machine keeps
// the registration - old binary, old config path - that the installer just
// replaced.
func replaceRegistration(cfg policy.Config, configPath string) error {
	_ = setDisabled(true)
	time.Sleep(replaceWait)
	s, err := New(cfg, configPath)
	if err != nil {
		return err
	}
	// Stop, and then wait for it to actually be stopped. Control returns as soon
	// as the SCM accepts the request, and deleting a service that is still running
	// leaves its *name* reserved until the process exits - so a create in that
	// window fails, and "replace the registration" becomes "remove the
	// registration and fail to make a new one". That leaves the machine with no
	// service at all, which is worse than the refusal this whole path replaced.
	_ = controlService(s, "stop")
	waitUntil(func() bool { return !serviceRunning(ServiceName) }, stopWait)
	return controlService(s, "uninstall")
}

// waitUntil polls done until it reports true or the timeout passes. It does not
// say which happened: every caller here is followed by the operation that was
// being waited for, and that operation's own error is the better answer.
func waitUntil(done func() bool, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for !done() {
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(pollInterval)
	}
}

// install (re)registers + hardens + starts. Shared by Install and the watchdog.
func install(cfg policy.Config, configPath string) error {
	s, err := New(cfg, configPath)
	if err != nil {
		return err
	}
	if err := createService(s); err != nil {
		return err
	}
	if err := serviceHarden(ServiceName); err != nil {
		return err
	}
	return controlService(s, "start")
}

// createService registers the service, retrying while the name is still held.
//
// After a removal the SCM keeps the name reserved until the last handle to the
// old service closes, and the wait in replaceRegistration narrows that window
// without closing it - a handle held by services.msc or by anything else that
// looked at the service keeps it open too. The message the create fails with is
// localized, so this retries on any error and returns the last one rather than
// trying to recognize that particular failure by its text.
func createService(s service.Service) error {
	deadline := time.Now().Add(createWait)
	for {
		err := controlService(s, "install")
		if err == nil || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(pollInterval)
	}
}

// Uninstall sets the disabled sentinel (so the watchdog stops resurrecting),
// waits long enough for the watchdog to observe it and exit, then stops and
// removes the service. The wait closes a race where the watchdog could
// re-install the service mid-teardown.
func Uninstall(cfg policy.Config, configPath string) error {
	_ = setDisabled(true)
	time.Sleep(replaceWait)
	s, err := New(cfg, configPath)
	if err != nil {
		return err
	}
	// A registration that is already gone is this function's goal, not its error.
	// Refusing here is what stops somebody removing the program at all after a
	// failed install took the service with it - and an uninstall that cannot be
	// run is the one failure mode a blocker must never have, because it is
	// indistinguishable from the program refusing to let itself be removed.
	if serviceExists(ServiceName) {
		_ = controlService(s, "stop")
		waitUntil(func() bool { return !serviceRunning(ServiceName) }, stopWait)
		if err := controlService(s, "uninstall"); err != nil {
			return err
		}
	}
	// Lift what every enforcer holds too, so an authorized uninstall fully
	// restores the machine - otherwise the extensions stay locked with no service
	// left to manage the lock.
	return defaultEnforcers().Remove(cfg)
}

// Pause turns protection off and keeps the guard running.
//
// This used to be an uninstall - Disable was literally Uninstall - and that one
// line was the reason a pause could never end on its own. With the service gone
// there was nothing left to notice a deadline, nothing to resume, nothing
// re-asserting the trusted config, and nothing writing the activity log during
// exactly the window protection was off. A pause with a deadline is only
// meaningful if something outlives it.
//
// So the service stays installed, stays running, and stays watched by the
// watchdog; it simply enforces nothing (see program.reapply). A zero until means
// an indefinite pause. The caller lifts the enforcement itself, so protection
// goes off the moment the command returns rather than on the service's next
// cycle - see the disable case in cmd/guard.
func Pause(cfg policy.Config, configPath string, until time.Time) error {
	return scm.Pause(until)
}

// Resume ends a pause and puts the guard back the way it should be.
//
// Clearing the pause is usually all it takes, because the service never went
// away. Two cases need more: a machine paused by a build that predates this
// change has no service at all, and an uninstall leaves the teardown sentinel
// set. Both are repaired by installing, which is idempotent - so Resume doubles
// as the migration path off the old teardown-style pause.
func Resume(cfg policy.Config, configPath string) error {
	if err := scm.Resume(); err != nil {
		return err
	}
	if scm.IsDisabled() || !scm.Exists(ServiceName) {
		return Install(cfg, configPath)
	}
	if _, err := scm.EnsureRunning(ServiceName); err != nil {
		return err
	}
	return nil
}

// RunWatchdog is the watchdog companion loop. A single instance runs at a time;
// it exits when the disabled sentinel is set.
func RunWatchdog(cfg policy.Config, configPath string) error {
	log.SetPrefix("watchdog: ")
	if !scm.AcquireSingleton(watchdogMutex) {
		log.Println("another watchdog is already running; exiting")
		return nil
	}
	for {
		if scm.IsDisabled() {
			log.Println("guard disabled by an authorized uninstall; watchdog exiting")
			return nil
		}
		if scm.IsUpdating() {
			// An update is swapping the binaries and restarting the service. Stand
			// down and exit so we neither fight the restart nor keep an old-binary
			// watchdog alive: releasing the singleton lets the freshly started
			// service spawn a watchdog from the updated binary.
			log.Println("update in progress; watchdog standing down")
			return nil
		}
		if scm.Exists(ServiceName) {
			if err := scm.Harden(ServiceName); err != nil {
				log.Printf("re-harden: %v", err)
			}
			if action, err := scm.EnsureRunning(ServiceName); err != nil {
				log.Printf("ensure running: %v", err)
			} else if action != "ok" {
				log.Printf("service %s", action)
			}
		} else {
			log.Println("service entry missing; re-installing")
			if err := install(cfg, configPath); err != nil {
				log.Printf("re-install: %v", err)
			}
		}
		time.Sleep(watchdogInterval)
	}
}

func (p *program) Start(s service.Service) error {
	p.logger.Info("Ward starting")
	// The service runs as SYSTEM, which makes it the right - and normally the
	// first - place to create the activity log and stamp its permissions. Nothing
	// unprivileged may create it, so until this has run the window and the
	// refused-launch handler have nowhere to append. See internal/activity.
	if err := activity.Provision(); err != nil {
		p.logger.Warningf("activity log unavailable: %v", err)
	}
	// The usage ledger is created here for the same reasons and by the same
	// reasoning as the log above: SYSTEM is the right owner, nothing unprivileged
	// may create it, and the service is normally the first thing to run.
	go p.loop()
	return nil
}

func (p *program) Stop(s service.Service) error {
	p.logger.Info("Ward stopping")
	// Recorded even though a stop is usually authorized (a pause, or an update
	// swapping binaries). "The guard was not running between 02:10 and 07:30" is
	// exactly the kind of gap the record exists to make visible, and the reason it
	// stopped is a separate entry either side of this one.
	activity.Record(activity.Event{Kind: activity.ServiceStopped})
	close(p.quit)
	if p.w != nil {
		p.w.Stop()
	}
	// In an interactive debug session, kill the watchdog so it doesn't outlive
	// the console. Under the real service manager we deliberately leave it
	// running so it can resurrect the service after a graceful stop.
	if p.interactive {
		p.mu.Lock()
		if p.dog != nil && p.dog.Process != nil {
			_ = p.dog.Process.Kill()
		}
		p.mu.Unlock()
	}
	return nil
}

func (p *program) loop() {
	// A running service means any update handoff is complete: clear a stale
	// "updating" flag (in case an updater died mid-swap) and remove leftover
	// ".old" binaries the reboot-delete may not have reached.
	_ = scm.SetUpdating(false)
	if exe, err := os.Executable(); err == nil {
		updater.CleanupOld(filepath.Dir(exe))
	}

	// Before the first apply, so a corrected store id is enforced on this start
	// rather than the next one.
	p.adoptCatalog()

	p.reapply("startup")

	if w, err := watcher.New(); err != nil {
		p.logger.Errorf("watcher init failed, relying on periodic re-apply: %v", err)
	} else {
		p.w = w
		go func() {
			if err := w.Run(func() { p.reapply(reasonRegistryChange) }); err != nil {
				p.logger.Errorf("watcher stopped: %v", err)
			}
		}()
	}

	if !scm.IsDisabled() && !scm.IsUpdating() {
		p.spawnWatchdog()
	}

	ticker := time.NewTicker(backstop)
	defer ticker.Stop()
	pauseTicker := time.NewTicker(pauseTick)
	defer pauseTicker.Stop()
	updateTicker := time.NewTicker(updateCheckInterval)
	defer updateTicker.Stop()
	firstUpdate := time.NewTimer(updateStartupDelay)
	defer firstUpdate.Stop()
	for {
		select {
		case <-p.quit:
			return
		case <-ticker.C:
			p.reapply("periodic")
		case <-pauseTicker.C:
			// A pause that has just run out has to put protection back promptly, and
			// waiting for the 30s backstop would be thirty seconds of a pause the user
			// was told had ended.
			p.checkPause()
		case <-updateTicker.C:
			p.checkForUpdate()
		}
	}
}

// checkForUpdate polls GitHub for a newer release and reacts per the configured
// AutoUpdate mode: "off" skips the check, "notify" logs availability, and
// "apply" launches `guard update` in a separate process to perform the
// cooperative swap (it must outlive this service, which it stops and restarts).
// Dev builds never auto-apply.
func (p *program) checkForUpdate() {
	mode := p.updateMode()
	if mode == policy.UpdateOff {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
	defer cancel()
	rel, err := updater.CheckLatest(ctx)
	if err != nil {
		p.logger.Infof("update check failed: %v", err)
		return
	}
	if !rel.Newer(buildinfo.Version) {
		return
	}
	if mode != policy.UpdateApply || buildinfo.Version == "dev" {
		p.logger.Infof("update available: %s (running %s); auto-apply off (mode=%q)", rel.Version, buildinfo.Version, mode)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		p.logger.Errorf("update: locate executable: %v", err)
		return
	}
	p.logger.Infof("applying update %s -> %s", buildinfo.Version, rel.Version)
	cmd := exec.Command(exe, "-config", p.configPath, "update")
	if err := cmd.Start(); err != nil {
		p.logger.Errorf("update: launch updater: %v", err)
		return
	}
	// Detach: the updater stops this service shortly, so we must not wait on it.
	_ = cmd.Process.Release()
}

// spawnWatchdog launches the watchdog child and respawns it if it exits while
// the service is still running and not disabled.
func (p *program) spawnWatchdog() {
	exe, err := os.Executable()
	if err != nil {
		p.logger.Errorf("locate executable for watchdog: %v", err)
		return
	}
	cmd := exec.Command(exe, "-config", p.configPath, "watchdog")
	if err := cmd.Start(); err != nil {
		p.logger.Errorf("start watchdog: %v", err)
		return
	}
	p.mu.Lock()
	p.dog = cmd
	p.mu.Unlock()

	go func() {
		_ = cmd.Wait()
		select {
		case <-p.quit:
			return // service stopping; do not respawn
		default:
		}
		if scm.IsDisabled() || scm.IsUpdating() {
			return // authorized teardown or in-progress update; leave it down
		}
		time.Sleep(watchdogRespawn)
		p.spawnWatchdog()
	}()
}

// adoptCatalog brings the config's per-browser store ids up to date from the
// catalog compiled into this binary, once per service start.
//
// This is what makes a corrected id reach a machine that already has a config.
// None of the other three paths carry it: the installer lays the template down
// with onlyifdoesntexist and so keeps the config it finds, `select` runs on
// first install only, and the in-app updater ships the binaries and nothing
// else. Without this, the machines with the right ids are only the ones
// installed after the fix. See policy.AdoptCatalog for the narrow set of things
// it will touch - and, more to the point, everything it will not.
//
// It belongs to the service and nowhere else. This is the one path that runs as
// SYSTEM on every start, so it is the only one that can record the trusted copy;
// and a reader doing it would walk into the trap policy.LoadEnforced documents,
// where defaultConfigPath resolves to whatever extension-ids.json happens to be
// above the working directory and the write lands in somebody's repository.
//
// p.cfg is left alone: reapply reloads through LoadTrusted immediately after
// this returns and picks the committed config up on its own. Setting it here as
// well would give the same value two writers.
//
// Every failure is logged and otherwise ignored. Enforcing the ids we already
// have beats enforcing nothing, and the next start tries again.
func (p *program) adoptCatalog() {
	cat, err := policy.EmbeddedCatalog()
	if err != nil {
		p.logger.Errorf("read the built-in store catalog: %v", err)
		return
	}
	cfg, _, err := policy.LoadTrusted(p.configPath)
	if err != nil {
		p.logger.Errorf("load the config before adopting the store catalog: %v", err)
		return
	}
	updated, changes := cfg.AdoptCatalog(cat)
	if len(changes) == 0 {
		return
	}
	if err := policy.Commit(updated, p.configPath); err != nil {
		p.logger.Errorf("record the corrected store ids: %v", err)
		return
	}
	for _, c := range changes {
		p.logger.Infof("store catalog: %s", c)
	}
	// The version is the Target because it answers the question the line raises:
	// a reader who sees their ids change wants to know what changed them.
	activity.Record(activity.Event{
		Kind:   activity.CatalogAdopted,
		Target: buildinfo.Version,
		Detail: strings.Join(changes, "; "),
	})
}

// reapply writes the policy and logs only when it actually fixed something (the
// locked-browser count changed), keeping the log quiet in steady state.
//
// It reloads the config each cycle, so an authorized enable/disable takes effect
// without a restart. The reload goes through policy.LoadTrusted rather than
// reading the file directly: an unauthorized edit to extension-ids.json - the
// obvious way to switch enforcement off without knowing the password - loses to
// the trusted copy and gets rewritten, the same way registry tamper loses to the
// policy we re-apply below.
func (p *program) reapply(reason string) {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()

	cfg, trust, err := policy.LoadTrusted(p.configPath)
	if err != nil {
		p.logger.Errorf("load config (%s): %v", reason, err)
	} else {
		if trust == policy.TrustRepaired {
			p.logger.Warningf("config was modified outside the guard; restored the trusted copy (%s)", reason)
			// Throttled: a process rewriting the file in a loop would otherwise fill
			// the record with the same line and bury everything around it. One entry
			// a minute is enough to show that it is happening.
			activity.RecordThrottled("tamper.config", tamperThrottle, activity.Event{
				Kind:   activity.TamperConfig,
				Detail: "noticed on the " + reason + " check",
			})
		}
		p.cfg = cfg
	}

	// A pause is a state the service holds, not a state it is absent for. Lift
	// everything once when one starts and then leave the machine alone: re-running
	// Remove on every cycle would rewrite the same keys for the length of the
	// pause, and would fight anything else that legitimately set them while
	// protection was off.
	if pause := p.pausedAt(); pause.Paused {
		if !p.paused {
			p.paused = true
			if err := p.enforcers.Remove(p.cfg); err != nil {
				p.logger.Errorf("lift protection for the pause (%s): %v", reason, err)
			}
			p.logger.Infof("protection paused (%s)", pauseSummary(pause))
		}
		return
	}
	if p.paused {
		// The pause ended - either somebody resumed it, or its deadline passed and
		// scm.Paused now reads as not paused all by itself. Fall through and apply.
		p.paused = false
		p.logger.Info("pause over; re-applying protection")
	}

	active := p.cfg
	set := p.enforcers
	before := enforce.EnforcedCount(set.Verify(active))
	if err := set.Apply(active); err != nil {
		p.logger.Errorf("apply (%s): %v", reason, err)
		return
	}
	if after := enforce.EnforcedCount(set.Verify(active)); after != before {
		p.logger.Infof("re-applied after %s: enforced %d -> %d", reason, before, after)
		p.recordPolicyTamper(reason, before, after)
	}
}

// recordPolicyTamper notes in the activity log that enforcement had drifted and
// was put back.
//
// Only the watcher's reason qualifies, and only an increase. The other reasons
// reach this code path for innocent reasons - startup goes from nothing to
// everything, and a schedule boundary legitimately changes how much is enforced -
// so recording those would put "protection was tampered with" in the record on
// days nobody touched anything. A line that serious has to mean it, so this
// reports the one case where something outside the guard demonstrably changed a
// policy key that the guard then corrected. A re-apply triggered by the guard's
// own write is excluded for free: nothing had drifted, so the count is unchanged.
func (p *program) recordPolicyTamper(reason string, before, after int) {
	if !isCorrectedTamper(reason, before, after) {
		return
	}
	activity.RecordThrottled("tamper.policy", tamperThrottle, activity.Event{
		Kind:   activity.TamperPolicy,
		Detail: fmt.Sprintf("a policy key had been changed; enforcement went from %d back to %d", before, after),
	})
}

// isCorrectedTamper is the rule recordPolicyTamper applies, split out so it can
// be pinned by a test: it decides whether a line saying protection was tampered
// with appears in somebody's record, and getting it wrong in either direction is
// worse than most bugs here - a false one is an accusation, a missed one is the
// event the log exists for.
func isCorrectedTamper(reason string, before, after int) bool {
	return reason == reasonRegistryChange && after > before
}

func (p *program) checkPause() {
	p.applyMu.Lock()
	ended := p.paused && !p.pausedAt().Paused
	p.applyMu.Unlock()
	if !ended {
		return
	}
	activity.Record(activity.Event{
		Kind:   activity.ProtectionResumed,
		Detail: "the pause ran out",
	})
	p.reapply("pause ended")
}

// pauseSummary describes a pause for the service log.
func pauseSummary(p scm.PauseState) string {
	if p.Indefinite() {
		return "until it is turned back on"
	}
	return "until " + p.Until.Local().Format(time.RFC1123)
}

func (p *program) updateMode() string {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	return p.cfg.UpdateMode()
}
