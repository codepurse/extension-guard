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
	"sync"
	"time"

	"github.com/kardianos/service"

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
	appSweepTick     = 1 * time.Second
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
	// agent is the helper running in the interactive user's session, present only
	// while a window-title rule is configured. See agent_windows.go.
	agent *sessionAgent
}

// New builds the service. configPath is embedded into the service's launch
// arguments so the Service Control Manager passes it back to `guard run` - a
// service's working directory is System32, so the config can't be located by
// walking up the tree. Flags precede the subcommand because Go's flag parser
// stops at the first non-flag argument.
func New(cfg policy.Config, configPath string) (service.Service, error) {
	prg := &program{cfg: cfg, configPath: configPath, quit: make(chan struct{})}
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

// Disable temporarily turns protection off. It performs the same teardown as an
// uninstall - stop and remove the service and lift the browser lock so browsing
// is unfiltered - but the caller deliberately keeps the stored uninstall
// password, and the trusted config, so Enable can restore protection later. Both
// outlive a pause on purpose: clearing the trusted config here would let someone
// pause protection, edit extension-ids.json, and have the edit adopted as
// authoritative when they enable again. The disabled sentinel it
// sets also stops the watchdog from resurrecting anything, and because the
// service entry is removed nothing auto-starts on reboot.
func Disable(cfg policy.Config, configPath string) error {
	return Uninstall(cfg, configPath)
}

// Enable restores protection after a Disable: it clears the disabled sentinel
// and reinstalls, hardens, and starts the service, which re-applies the browser
// lock. It assumes an uninstall password is already stored (set at install).
func Enable(cfg policy.Config, configPath string) error {
	return Install(cfg, configPath)
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
	go p.loop()
	return nil
}

func (p *program) Stop(s service.Service) error {
	p.logger.Info("Extension Guard stopping")
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
			if err := w.Run(func() { p.reapply("registry change") }); err != nil {
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
			p.checkSchedule()
		case <-appTicker.C:
			p.sweepApps()
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
		}
		p.cfg = cfg
	}

	now := time.Now()
	active := p.resolve(now)
	p.activeSig = p.cfg.ActiveSignature(now)

	set := enforce.Default()
	before := enforce.EnforcedCount(set.Verify(active))
	if err := set.Apply(active); err != nil {
		p.logger.Errorf("apply (%s): %v", reason, err)
		return
	}
	if after := enforce.EnforcedCount(set.Verify(active)); after != before {
		p.logger.Infof("re-applied after %s: enforced %d -> %d", reason, before, after)
	}
	p.ensureAgent(active)
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

// resolve narrows the config to what should be enforced right now, logging any
// schedule problem that made policy.EnforcedAt fall back to ignoring it.
//
// Callers must hold applyMu.
func (p *program) resolve(now time.Time) policy.Config {
	active, err := p.cfg.EnforcedAt(now)
	if err != nil {
		p.logger.Errorf("invalid schedule (%v); enforcing every enabled extension until it is corrected", err)
	}
	return active
}

// checkSchedule re-applies only when a block boundary has been crossed since the
// last apply. It runs every few seconds, so it deliberately does no registry work
// to decide - comparing the resolved signature is pure computation.
func (p *program) checkSchedule() {
	p.applyMu.Lock()
	changed := p.cfg.ActiveSignature(time.Now()) != p.activeSig
	p.applyMu.Unlock()
	if changed {
		p.reapply("schedule")
	}
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

	if !p.cfg.AnyApps() {
		return // nothing configured; do not even look at the process list
	}
	active, _ := p.cfg.EnforcedAt(time.Now())
	err := enforce.Default().Sweep(active)
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
