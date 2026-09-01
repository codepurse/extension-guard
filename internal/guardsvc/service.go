// Package guardsvc hosts the Extension Guard as a long-running service and its
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
	"github.com/codepurse/extension-guard/internal/usage"
	"github.com/codepurse/extension-guard/internal/watcher"
)

const (
	// ServiceName is the SCM service name; the watchdog references it too.
	ServiceName = "ExtensionGuard"

	backstop = 30 * time.Second
	// scheduleTick is how often the service checks whether a block boundary has
	// been crossed. It only compares a computed signature - no registry work - so
	// it can run far more often than the backstop, which matters because being
	// late to *start* enforcing is a hole a user could walk through.
	scheduleTick = 5 * time.Second
	// appSweepTick is how often blocked applications are swept. It has to be fast:
	// unlike a browser policy, which the browser then honours on its own, an
	// application the guard has not looked at yet is an application that is
	// running, and every second of that is a second the block visibly failed. The
	// sweep does no registry work and returns immediately when no app rules are
	// configured, so an install that blocks only extensions and sites pays nothing
	// for this ticker.
	appSweepTick = 1 * time.Second
	// usageFlushTick is how often the daily-limit counters are written to disk.
	// They are charged every second, in memory, and flushed on this interval plus
	// whenever a limit is reached - see internal/usage for why not every second.
	// The interval is also the most a power cut can give back: half a minute of a
	// budget, once, is a cost worth paying to avoid a file rewrite per second.
	usageFlushTick = 30 * time.Second
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

	// applyMu serializes reapply and guards cfg and activeSig. Several goroutines
	// reach them - the main loop, the registry watcher's callback, the schedule
	// ticker and the app sweep - and two concurrent applies would race each other
	// writing the same policy keys.
	applyMu   sync.Mutex
	activeSig string
	// lastSweepErr is the last app-sweep failure that was logged. The sweep runs
	// every second, so a persistent failure (a process owned by an account we
	// cannot touch) would otherwise fill the event log with the same line; it is
	// logged when it changes and then held. lastAgentErr does the same for the
	// session agent, which is re-checked on every re-apply.
	lastSweepErr string
	lastAgentErr string
	// lastSampleErr and lastUsageErr hold the same trick for the two halves of
	// daily-limit accounting: measuring it (every second) and writing it down
	// (every thirty).
	lastSampleErr string
	lastUsageErr  string
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
	// agent is the helper running in the interactive user's session, present only
	// while a window-title rule is configured. See agent_windows.go.
	agent *sessionAgent
	// usage counts how long each limited block has been used today. The service
	// owns the only writer, and resolves enforcement against these live counters
	// rather than the file it flushes them to - a budget that ran out four seconds
	// ago has to be enforced now, not after the next flush. Guarded by applyMu with
	// everything else that reads cfg.
	usage *usage.Tracker
	// usageDay is the day the counters below belong to, and exhausted is the set of
	// blocks whose budget had run out the last time it was checked. Both exist to
	// spot the *transition*: a limit being reached is worth recording once, not
	// once a second for the rest of the evening.
	usageDay  string
	exhausted map[string]bool
	// lastSkew is the clock offset last reported, so a clock that has been moved is
	// logged when it moves and not once a second for as long as it stays wrong -
	// the same reason usageDay and exhausted exist.
	lastSkew time.Duration
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
		DisplayName: "Extension Guard",
		Description: "Keeps the configured browser extensions force-installed and re-applies the policy if it is tampered with.",
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

// Install registers the service, hardens it (recovery + Automatic start),
// clears the disabled sentinel, and starts it.
func Install(cfg policy.Config, configPath string) error {
	if err := scm.SetDisabled(false); err != nil {
		return err
	}
	return install(cfg, configPath)
}

// install (re)registers + hardens + starts. Shared by Install and the watchdog.
func install(cfg policy.Config, configPath string) error {
	s, err := New(cfg, configPath)
	if err != nil {
		return err
	}
	if err := service.Control(s, "install"); err != nil {
		return err
	}
	if err := scm.Harden(ServiceName); err != nil {
		return err
	}
	return service.Control(s, "start")
}

// Uninstall sets the disabled sentinel (so the watchdog stops resurrecting),
// waits long enough for the watchdog to observe it and exit, then stops and
// removes the service. The wait closes a race where the watchdog could
// re-install the service mid-teardown.
func Uninstall(cfg policy.Config, configPath string) error {
	_ = scm.SetDisabled(true)
	time.Sleep(watchdogInterval + 2*time.Second)
	s, err := New(cfg, configPath)
	if err != nil {
		return err
	}
	_ = service.Control(s, "stop")
	if err := service.Control(s, "uninstall"); err != nil {
		return err
	}
	// Lift what every enforcer holds too, so an authorized uninstall fully
	// restores the machine - otherwise the extensions stay locked with no service
	// left to manage the lock.
	return enforce.Default().Remove(cfg)
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
	p.logger.Info("Extension Guard starting")
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
	if err := usage.Provision(); err != nil {
		p.logger.Warningf("usage ledger unavailable, so daily limits may not be counted: %v", err)
	}
	// Loading is what makes a limit survive a restart. A tracker that started empty
	// would hand back the whole day's budget every time the service was restarted,
	// which is a bypass that costs one `net stop`.
	p.usage = usage.NewTracker()
	if p.usage.State() == usage.StateUnreadable {
		// Rebuild it now rather than waiting for the flush ticker. While the state
		// holds, every limit reads as spent, so a limited application is blocked - and
		// a blocked application cannot run, so nothing would ever be charged and
		// nothing flushed. Failing closed has to be a moment, not a trap.
		//
		// It is recorded because it looks exactly like what it might be. The counters
		// that were in the damaged file are gone, so this is a budget coming back, and
		// a budget coming back belongs in the record next to every other way that can
		// happen.
		p.logger.Warningf("usage ledger at %s could not be read; starting today's counts again", usage.Path())
		if err := p.usage.Flush(); err != nil {
			p.logger.Errorf("rebuild usage ledger: %v", err)
		}
		activity.Record(activity.Event{Kind: activity.UsageReset, Detail: "it could not be read, so today's daily limits start again from zero"})
	}
	activity.Record(activity.Event{Kind: activity.ServiceStarted, Target: buildinfo.Version})
	go p.loop()
	return nil
}

func (p *program) Stop(s service.Service) error {
	p.logger.Info("Extension Guard stopping")
	// Recorded even though a stop is usually authorized (a pause, or an update
	// swapping binaries). "The guard was not running between 02:10 and 07:30" is
	// exactly the kind of gap the record exists to make visible, and the reason it
	// stopped is a separate entry either side of this one.
	activity.Record(activity.Event{Kind: activity.ServiceStopped})
	// Flush before anything else: the counters in memory are ahead of the file, and
	// a stop that dropped them would return whatever had been spent since the last
	// flush. Cheap, and it is the difference between a stop being a pause and a
	// stop being a way to get thirty seconds back.
	if p.usage != nil {
		if err := p.usage.Flush(); err != nil {
			p.logger.Warningf("write usage ledger on stop: %v", err)
		}
	}
	close(p.quit)
	if p.w != nil {
		p.w.Stop()
	}
	// The session helper enforces nothing on its own once we are gone, and an
	// orphan sweeping in the user's session would be enforcement nobody is
	// managing. It also exits by itself when it sees the service stop.
	p.applyMu.Lock()
	stopSessionAgent(p.agent)
	p.agent = nil
	p.applyMu.Unlock()
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
	schedTicker := time.NewTicker(scheduleTick)
	defer schedTicker.Stop()
	appTicker := time.NewTicker(appSweepTick)
	defer appTicker.Stop()
	usageTicker := time.NewTicker(usageFlushTick)
	defer usageTicker.Stop()
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
		case <-schedTicker.C:
			// Before the schedule: a pause that has just run out has to put
			// protection back promptly, and waiting for the 30s backstop would be
			// thirty seconds of a pause the user was told had ended.
			p.checkPause()
			p.checkSchedule()
		case <-appTicker.C:
			// Measure first, then sweep. Charging the last second before resolving
			// means a budget that has just run out is enforced on this tick rather
			// than the next one, and the sweep that follows closes the application
			// the moment it stops being allowed.
			if p.measureUsage() {
				p.reapply("time limit")
			}
			p.sweepApps()
		case <-usageTicker.C:
			p.flushUsage()
		case <-firstUpdate.C:
			p.checkForUpdate()
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
			stopSessionAgent(p.agent)
			p.agent = nil
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

	now := time.Now()
	spent := p.spent(now)
	active := p.resolve(now, spent)
	// The same counters decide both, deliberately. Resolving against live counters
	// and then signing against the file would make the signature disagree with what
	// was just applied for as long as the flush interval, and the schedule ticker
	// would re-apply every few seconds trying to reconcile a difference that is not
	// there.
	p.activeSig = p.cfg.ActiveSignatureWith(now, spent)

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
	p.ensureAgent(active)
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

// ensureAgent keeps the session helper running while a window-title rule needs it,
// and shuts it down when none does. It is driven from reapply rather than from the
// sweep ticker: starting a process is not something to attempt every second, and a
// helper that appears within 30 seconds of someone signing in is soon enough for a
// rule that only matches windows they have opened since.
//
// Callers must hold applyMu.
func (p *program) ensureAgent(active policy.Config) {
	// An interactive `guard run` is already in the user's session, so it can see
	// the windows itself and a helper would only duplicate the work.
	if !policy.NeedsTitles(active.BlockedApps()) || p.interactive {
		stopSessionAgent(p.agent)
		p.agent = nil
		return
	}
	exe, err := os.Executable()
	if err != nil {
		p.logAgent(fmt.Sprintf("locate executable: %v", err))
		return
	}
	agent, err := ensureSessionAgent(p.agent, exe, p.configPath)
	p.agent = agent
	if err != nil {
		p.logAgent(err.Error())
		return
	}
	p.logAgent("")
}

// logAgent reports a change in the session agent's health, once. Nobody signed in
// is the common case on a server or a locked machine, and it must not fill the log.
func (p *program) logAgent(msg string) {
	if msg == p.lastAgentErr {
		return
	}
	if msg != "" {
		p.logger.Warningf("session agent unavailable, so window-title rules are not enforced: %s", msg)
	} else if p.lastAgentErr != "" {
		p.logger.Infof("session agent running; window-title rules are enforced again")
	}
	p.lastAgentErr = msg
}

// reportSkew logs and records a clock that has been moved far enough for the
// tracker to stop believing it, and again when it comes back.
//
// It reports the transition rather than the state, like every other once-a-second
// check here. A limit being got around is worth a line in the record; the same
// line every second for the rest of the evening is worth nothing.
//
// Callers must hold applyMu.
func (p *program) reportSkew() {
	skew := p.usage.Skew()
	if skew == p.lastSkew {
		return
	}
	switch {
	case skew == 0:
		p.logger.Infof("the system clock agrees with the guard again")
		activity.Record(activity.Event{Kind: activity.ClockChanged, Detail: "back in agreement"})
	default:
		p.logger.Warningf("the system clock is %s from the guard's own reckoning; daily limits are being counted against the real day, not the clock", policy.HumanDuration(abs(skew)))
		activity.Record(activity.Event{
			Kind:   activity.ClockChanged,
			Detail: describeSkew(skew),
		})
	}
	p.lastSkew = skew
}

// describeSkew says which way the clock was moved, in the words somebody reading
// the activity log would use.
func describeSkew(d time.Duration) string {
	if d < 0 {
		return "moved back " + policy.HumanDuration(-d) + "; daily limits ignored it"
	}
	return "moved forward " + policy.HumanDuration(d) + "; daily limits ignored it"
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// spent is the service's view of how much of each daily budget has gone. It comes
// from the live tracker rather than the ledger file, because the file is up to a
// flush interval behind and enforcement cannot be.
//
// Callers must hold applyMu.
func (p *program) spent(now time.Time) policy.Spent {
	if p.usage == nil {
		return p.cfg.SpentAt(now) // no tracker yet: read the ledger, which fails closed
	}
	// The tracker's clock, not the machine's. Winding the wall clock past the reset
	// hour would otherwise name a day with nothing charged against it and hand back
	// a whole fresh budget - see usage.Tracker.Now.
	return policy.Spent{
		ByBlock:    p.usage.Spent(p.cfg.DayKey(p.usage.Now(now))),
		Unreadable: p.usage.State() == usage.StateUnreadable,
	}
}

// resolve narrows the config to what should be enforced right now, logging any
// schedule problem that made policy.EnforcedAt fall back to ignoring it.
//
// Callers must hold applyMu.
func (p *program) resolve(now time.Time, spent policy.Spent) policy.Config {
	active, err := p.cfg.EnforcedAtWith(now, spent)
	if err != nil {
		p.logger.Errorf("invalid schedule (%v); enforcing every enabled extension until it is corrected", err)
	}
	return active
}

// checkPause re-applies when a pause has ended since the last cycle.
//
// It only has to notice, not to decide. A bounded pause expires by the clock in
// scm.Paused, so protection is already considered on the moment the deadline
// passes, whether or not anything is running - this is what turns that back into
// enforcement, promptly. The reverse direction (a pause starting) needs no
// watcher because the command that starts one lifts enforcement itself.
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

// checkSchedule re-applies only when a block boundary has been crossed since the
// last apply. It runs every few seconds, so it deliberately does no registry work
// to decide - comparing the resolved signature is pure computation.
func (p *program) checkSchedule() {
	p.applyMu.Lock()
	now := time.Now()
	changed := p.cfg.ActiveSignatureWith(now, p.spent(now)) != p.activeSig
	p.applyMu.Unlock()
	if changed {
		p.reapply("schedule")
	}
}

// measureUsage charges the time since the last observation to every limited block
// being used right now, and reports whether one of them has just run out - which
// the caller turns into an immediate re-apply, because a budget reaching zero has
// to start a launch block, not only close what is already open.
//
// It is also where the day rolling over is noticed. Nothing has to be reset for
// that: the counters are filed per day, so a new day is simply a key nobody has
// written to yet. Only the "already told them" set is cleared.
func (p *program) measureUsage() bool {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()

	if p.usage == nil {
		return false
	}
	if !p.cfg.AnyLimits() && !p.cfg.AnyApps() {
		return false // nothing configured; do not even look at the process list
	}
	now := time.Now()
	// Charged against the day the tracker believes it is, for the same reason the
	// read path uses it: the wall clock decides which day a limit is spent from,
	// and the wall clock belongs to the person being limited.
	day := p.cfg.DayKey(p.usage.Now(now))
	p.reportSkew()
	if day != p.usageDay {
		p.usageDay, p.exhausted = day, map[string]bool{}
	}

	sample, err := policy.SampleUsage(p.cfg, now)
	if err != nil {
		// Same throttling reasoning as the sweep: this runs every second, so a
		// persistent failure is logged when it changes and then held.
		p.logUsage(err.Error())
		return false
	}
	p.logUsage("")

	if p.paused {
		// Protection is off, so a daily budget must not be running down. Charging a
		// block here would mean an hour's pause quietly spends an hour of an
		// allowance that was not being enforced for any of it - the budget would be
		// gone by the time protection came back, for something the guard explicitly
		// permitted.
		//
		// The record is charged anyway, and that is the opposite decision on purpose.
		// It is not a budget, nothing is enforced from it, and it is the same choice
		// the activity log makes by recording what happens during a pause: a history
		// that went quiet during exactly the window usage runs highest would be worse
		// than no history. The pause itself is in the log next to it, so a reader can
		// see why an evening looks the way it does.
		p.usage.Observe(now, day, nil, sample.Apps)
		return false
	}
	p.usage.Observe(now, day, sample.Blocks, sample.Apps)

	// Report the transition, not the state. A block that ran out an hour ago is
	// still out, and saying so every second would bury everything else in the log.
	spent := p.spent(now)
	if spent.Unreadable {
		// Every limit reads as spent here, which is enforcement working as intended
		// but is not the same fact as a budget having been used up - and writing "the
		// daily limit was reached" for a block nobody touched would be a false entry
		// in a record kept for accountability. Startup rebuilds the ledger, so this is
		// a state measured in seconds.
		return false
	}
	crossed := false
	for _, b := range p.cfg.LimitedBlocks() {
		key := usage.Key(b.ID)
		out := b.Exhausted(spent)
		if out && !p.exhausted[key] {
			crossed = true
			limit, _ := b.LimitFor()
			activity.Record(activity.Event{
				Kind:   activity.LimitReached,
				Target: blockName(b),
				Detail: "the " + policy.HumanDuration(limit) + " a day it allows is used up; " + b.GovernedSummary() + " is blocked until the limit resets",
			})
		}
		p.exhausted[key] = out
	}
	if crossed {
		// Flush now rather than at the next interval, for two reasons. If the machine
		// loses power here, "the budget was spent" must be what comes back, not "there
		// were four minutes left" - this is the one moment where the exact number
		// matters. And the session agent, which enforces window-title rules where this
		// service cannot see them, resolves against the file rather than these
		// counters: writing at the crossing is what lets it notice within its own
		// second instead of within a flush interval.
		if err := p.usage.Flush(); err != nil {
			p.logger.Warningf("write usage ledger: %v", err)
		}
	}
	return crossed
}

// flushUsage writes the counters to disk on the flush ticker. Failures are logged
// once rather than every interval: the usual cause is somebody having taken the
// ledger away, which does not fix itself and does not need saying repeatedly.
func (p *program) flushUsage() {
	p.applyMu.Lock()
	tracker := p.usage
	p.applyMu.Unlock()
	if tracker == nil {
		return
	}
	msg := ""
	if err := tracker.Flush(); err != nil {
		msg = err.Error()
	}
	// Taken again for the bookkeeping only: the write above must not hold the lock
	// the one-second sweep needs.
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	if msg != p.lastUsageErr {
		if msg != "" {
			p.logger.Errorf("write usage ledger: %s", msg)
		} else {
			p.logger.Infof("usage ledger: writing again")
		}
		p.lastUsageErr = msg
	}
}

// logUsage reports a change in the measurement's health, once. Callers hold
// applyMu.
func (p *program) logUsage(msg string) {
	if msg == p.lastSampleErr {
		return
	}
	if msg != "" {
		p.logger.Errorf("measure usage, so daily limits are not being counted: %s", msg)
	} else if p.lastSampleErr != "" {
		p.logger.Infof("measuring usage again; daily limits are being counted")
	}
	p.lastSampleErr = msg
}

// blockName is what a block is called in the activity log: the name its author gave
// it, falling back to the id. The log is read by a person, and "Games" says more
// than "games-2".
func blockName(b policy.Block) string {
	if name := strings.TrimSpace(b.Label); name != "" {
		return name
	}
	return b.ID
}

// sweepApps closes any blocked application that is running. It is the one piece
// of enforcement that has to run continuously rather than being written once and
// honoured by something else, which is why it gets its own ticker instead of
// waiting for the 30s backstop - see enforce.Sweeper.
//
// It takes applyMu so it cannot race a re-apply writing the same launch-block
// keys, and it resolves the schedule without reporting a bad one: reapply already
// logs that every cycle, and repeating it every second would bury everything else.
func (p *program) sweepApps() {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()

	if p.paused {
		return // protection is off; closing an application now would be the guard
		// enforcing something it has just told the user it is not enforcing
	}
	if !p.cfg.AnyApps() {
		return // nothing configured; do not even look at the process list
	}
	now := time.Now()
	active, _ := p.cfg.EnforcedAtWith(now, p.spent(now))
	err := p.enforcers.Sweep(active)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg != p.lastSweepErr {
		if msg != "" {
			p.logger.Errorf("sweep: %s", msg)
		} else {
			p.logger.Infof("sweep: recovered")
		}
		p.lastSweepErr = msg
	}
}

// updateMode reads the configured auto-update mode under the lock, since the
// config is replaced by reapply on another goroutine.
func (p *program) updateMode() string {
	p.applyMu.Lock()
	defer p.applyMu.Unlock()
	return p.cfg.UpdateMode()
}
