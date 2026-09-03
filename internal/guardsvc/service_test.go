package guardsvc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kardianos/service"

	"github.com/codepurse/extension-guard/internal/enforce"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
)

// The service loop decides when protection is lifted and when it is put back,
// and until the enforcer set and the pause reader became fields there was no way
// to exercise any of it - both reach the real registry and the real browser
// policy, which a test may not touch.
//
// What is deliberately still real here: the config load, the schedule
// resolution, and the activity log (which stays disabled in tests, so nothing is
// written). Those are covered by their own packages; what these tests pin is the
// sequencing the loop is responsible for.

// fakeEnforcer stands in for the real backends and counts what it was asked to
// do. Verify reports whatever the last Apply or Remove left behind, so the
// before/after tally reapply computes behaves the way the real one does.
type fakeEnforcer struct {
	mu       sync.Mutex
	applies  int
	removes  int
	sweeps   int
	enforced bool
}

func (f *fakeEnforcer) Name() string { return "fake" }

func (f *fakeEnforcer) Apply(policy.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	f.enforced = true
	return nil
}

func (f *fakeEnforcer) Remove(policy.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removes++
	f.enforced = false
	return nil
}

func (f *fakeEnforcer) Sweep(policy.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweeps++
	return nil
}

func (f *fakeEnforcer) Verify(policy.Config) []enforce.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []enforce.Status{{Enforcer: "fake", Target: "browser", Present: true, Enforced: f.enforced}}
}

func (f *fakeEnforcer) counts() (applies, removes, sweeps int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applies, f.removes, f.sweeps
}

// quietLogger swallows the service log, which otherwise needs a real service
// manager to exist.
type quietLogger struct{}

func (quietLogger) Error(...interface{}) error            { return nil }
func (quietLogger) Warning(...interface{}) error          { return nil }
func (quietLogger) Info(...interface{}) error             { return nil }
func (quietLogger) Errorf(string, ...interface{}) error   { return nil }
func (quietLogger) Warningf(string, ...interface{}) error { return nil }
func (quietLogger) Infof(string, ...interface{}) error    { return nil }

// newTestProgram builds a program whose enforcement and pause state are under
// the test's control.
//
// interactive is set on purpose: it makes ensureAgent a no-op, so a machine
// whose trusted config happens to contain a window-title rule does not have a
// helper process spawned into its session by `go test`.
func newTestProgram(t *testing.T, paused func() scm.PauseState) (*program, *fakeEnforcer) {
	t.Helper()
	fake := &fakeEnforcer{}
	cfgPath := filepath.Join(t.TempDir(), "extension-ids.json")
	if err := os.WriteFile(cfgPath, []byte(`{"extensions":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return &program{
		configPath:  cfgPath,
		logger:      quietLogger{},
		quit:        make(chan struct{}),
		interactive: true,
		enforcers:   enforce.Set{fake},
		pausedAt:    paused,
	}, fake
}

func pausedForever() scm.PauseState { return scm.PauseState{Paused: true} }
func notPaused() scm.PauseState     { return scm.PauseState{} }

// A pause lifts enforcement once, not on every cycle. reapply runs on startup,
// on a 30-second backstop and on every registry change, so re-running Remove
// each time would rewrite the same keys for the whole length of the pause and
// fight anything else that legitimately set them while protection was off.
func TestAPauseLiftsEnforcementExactlyOnce(t *testing.T) {
	p, fake := newTestProgram(t, pausedForever)

	for i := 0; i < 4; i++ {
		p.reapply("periodic")
	}

	applies, removes, _ := fake.counts()
	if removes != 1 {
		t.Errorf("enforcement was lifted %d times over four cycles, want once", removes)
	}
	if applies != 0 {
		t.Errorf("enforcement was applied %d times while paused, want never", applies)
	}
	if !p.paused {
		t.Error("the paused latch was not set")
	}
}

// When the pause ends the next cycle has to put protection back, and clear the
// latch so the one after it behaves normally.
func TestEndingAPauseReAppliesEnforcement(t *testing.T) {
	live := true
	p, fake := newTestProgram(t, func() scm.PauseState {
		if live {
			return scm.PauseState{Paused: true}
		}
		return scm.PauseState{}
	})

	p.reapply("startup")
	if _, removes, _ := fake.counts(); removes != 1 {
		t.Fatalf("expected the pause to lift enforcement once, got %d", removes)
	}

	live = false
	p.reapply("periodic")

	if applies, _, _ := fake.counts(); applies != 1 {
		t.Errorf("enforcement was applied %d times after the pause ended, want once", applies)
	}
	if p.paused {
		t.Error("the paused latch survived the end of the pause")
	}
}

// A deadline that has run out ends the pause without anybody acting on it: the
// pause state simply stops reading as paused, and checkPause is what turns that
// back into enforcement.
func TestAnExpiredDeadlinePutsProtectionBack(t *testing.T) {
	now := time.Now()
	deadline := now.Add(30 * time.Minute)
	clock := now
	p, fake := newTestProgram(t, func() scm.PauseState {
		if clock.Before(deadline) {
			return scm.PauseState{Paused: true, Until: deadline}
		}
		return scm.PauseState{}
	})

	p.reapply("startup")
	if _, removes, _ := fake.counts(); removes != 1 {
		t.Fatalf("expected the pause to lift enforcement, got %d removes", removes)
	}

	// Still inside the deadline: nothing to do.
	p.checkPause()
	if applies, _, _ := fake.counts(); applies != 0 {
		t.Fatalf("protection came back before the deadline (%d applies)", applies)
	}

	clock = deadline.Add(time.Second)
	p.checkPause()

	if applies, _, _ := fake.counts(); applies != 1 {
		t.Errorf("enforcement was applied %d times after the deadline passed, want once", applies)
	}
	if p.paused {
		t.Error("the paused latch survived the deadline")
	}

	// And it does not keep re-applying every few seconds afterwards.
	p.checkPause()
	if applies, _, _ := fake.counts(); applies != 1 {
		t.Errorf("checkPause re-applied again after the pause had already ended (%d applies)", applies)
	}
}

// Closing an application while paused would be the guard enforcing something it
// has just told the user it is not enforcing.
func TestNothingIsSweptWhilePaused(t *testing.T) {
	p, fake := newTestProgram(t, pausedForever)
	p.reapply("startup")

	for i := 0; i < 3; i++ {
		p.sweepApps()
	}

	if _, _, sweeps := fake.counts(); sweeps != 0 {
		t.Errorf("swept %d times while paused, want never", sweeps)
	}
}

// A daily budget must not run down while protection is off, or an hour's pause
// silently spends an hour of an allowance that was not being enforced for any of
// it - and the budget is gone by the time protection comes back.
func TestBudgetsAreNotChargedWhilePaused(t *testing.T) {
	p, _ := newTestProgram(t, pausedForever)
	p.reapply("startup")

	if p.measureUsage() {
		t.Error("time was charged against a daily budget while protection was paused")
	}
}

// "Protection was tampered with" is an accusation, so the rule that puts one in
// the record is pinned here. Only the watcher's reason qualifies, and only an
// increase: startup goes from nothing to everything, and a schedule boundary or
// a limit running out legitimately changes how much is enforced.
func TestOnlyACorrectedPolicyChangeCountsAsTamper(t *testing.T) {
	cases := []struct {
		reason        string
		before, after int
		want          bool
	}{
		{reasonRegistryChange, 2, 4, true},
		{reasonRegistryChange, 4, 4, false}, // our own write; nothing had drifted
		{reasonRegistryChange, 4, 2, false}, // fewer enforced is not a correction
		{"startup", 0, 4, false},
		{"periodic", 2, 4, false},
		{"schedule", 2, 4, false},
		{"time limit", 2, 4, false},
		{"pause ended", 0, 4, false},
	}
	for _, c := range cases {
		if got := isCorrectedTamper(c.reason, c.before, c.after); got != c.want {
			t.Errorf("%s %d->%d: counted as tamper = %v, want %v", c.reason, c.before, c.after, got, c.want)
		}
	}
}

// With no pause in force the loop behaves as it always did.
func TestEnforcementIsAppliedWhenNothingIsPaused(t *testing.T) {
	p, fake := newTestProgram(t, notPaused)

	p.reapply("startup")

	applies, removes, _ := fake.counts()
	if applies != 1 {
		t.Errorf("enforcement was applied %d times, want once", applies)
	}
	if removes != 0 {
		t.Errorf("enforcement was lifted %d times with no pause in force, want never", removes)
	}
	if p.paused {
		t.Error("the paused latch was set with no pause in force")
	}
}

// Install used to fail outright when a registration was already there, which is
// what an installer re-run and every upgrade hit. These pin the replacement path
// - the ordering in particular, because the sentinel and the watchdog are what
// decide whether the new registration survives the swap.

// stubInstall replaces the service-control seams with recorders and restores
// them when the test ends. It returns the call log, in order.
func stubInstall(t *testing.T, exists bool, controlErr map[string]error) *[]string {
	t.Helper()
	oldExists, oldRunning, oldHarden := serviceExists, serviceRunning, serviceHarden
	oldDisabled, oldControl := setDisabled, controlService
	oldReplace, oldStop, oldCreate, oldPoll := replaceWait, stopWait, createWait, pollInterval
	oldEnforcers := defaultEnforcers
	t.Cleanup(func() {
		serviceExists, serviceRunning, serviceHarden = oldExists, oldRunning, oldHarden
		setDisabled, controlService = oldDisabled, oldControl
		replaceWait, stopWait, createWait, pollInterval = oldReplace, oldStop, oldCreate, oldPoll
		defaultEnforcers = oldEnforcers
	})
	// Uninstall lifts protection through this; the real set writes browser policy.
	defaultEnforcers = func() enforce.Set { return enforce.Set{} }

	var calls []string
	serviceExists = func(string) bool { return exists }
	serviceRunning = func(string) bool { return false }
	serviceHarden = func(string) error { calls = append(calls, "harden"); return nil }
	setDisabled = func(v bool) error {
		calls = append(calls, fmt.Sprintf("disabled=%v", v))
		return nil
	}
	controlService = func(_ service.Service, action string) error {
		calls = append(calls, action)
		return controlErr[action]
	}
	replaceWait, stopWait, pollInterval = 0, 0, 0
	createWait = time.Second
	return &calls
}

func TestInstallReplacesAnExistingRegistration(t *testing.T) {
	calls := stubInstall(t, true, nil)

	if err := Install(policy.Config{}, "cfg.json"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	want := []string{"disabled=true", "stop", "uninstall", "disabled=false", "install", "harden", "start"}
	if got := strings.Join(*calls, ","); got != strings.Join(want, ",") {
		t.Errorf("call order: got %v, want %v", *calls, want)
	}
}

func TestInstallOnACleanMachineTearsNothingDown(t *testing.T) {
	calls := stubInstall(t, false, nil)

	if err := Install(policy.Config{}, "cfg.json"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// No sentinel dance and no uninstall: there is nothing registered to replace,
	// and a fresh install must not open a window where protection is off.
	want := []string{"disabled=false", "install", "harden", "start"}
	if got := strings.Join(*calls, ","); got != strings.Join(want, ",") {
		t.Errorf("call order: got %v, want %v", *calls, want)
	}
}

// The failure that matters most. The sentinel is set before the swap, so an
// error partway through must not leave it set - that is the state in which the
// watchdog stands down and the old service, which is still registered, stops
// being guarded.
func TestAFailedReplaceDoesNotLeaveProtectionDisabled(t *testing.T) {
	calls := stubInstall(t, true, map[string]error{"uninstall": errors.New("access denied")})

	err := Install(policy.Config{}, "cfg.json")
	if err == nil {
		t.Fatal("Install: want an error when the existing registration cannot be removed")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("error should carry the cause, got %v", err)
	}

	last := (*calls)[len(*calls)-1]
	if last != "disabled=false" {
		t.Errorf("sentinel must be cleared on the failure path; last call was %q (%v)", last, *calls)
	}
	for _, c := range *calls {
		if c == "install" {
			t.Error("must not register a new service after failing to remove the old one")
		}
	}
}

// The bug this pins cost a machine its service outright. The SCM keeps a deleted
// service's name reserved until the old process exits, so the create that
// follows a removal can fail for a moment - and failing there left the old
// registration gone and no new one in its place.
func TestTheNewRegistrationIsRetriedWhileTheNameIsStillHeld(t *testing.T) {
	calls := stubInstall(t, true, nil)

	refusals := 2
	inner := controlService
	controlService = func(s service.Service, action string) error {
		err := inner(s, action)
		if action == "install" && refusals > 0 {
			refusals--
			return errors.New("the specified service has been marked for deletion")
		}
		return err
	}

	if err := Install(policy.Config{}, "cfg.json"); err != nil {
		t.Fatalf("Install should ride out a name that is still held: %v", err)
	}
	if refusals != 0 {
		t.Errorf("expected both refusals to be consumed, %d left", refusals)
	}
	// It has to reach start; a create that succeeded on the third try is still a
	// successful install and the service must end up running.
	if last := (*calls)[len(*calls)-1]; last != "start" {
		t.Errorf("install did not finish: last call %q (%v)", last, *calls)
	}
}

func TestARegistrationThatIsAlreadyGoneDoesNotBlockUninstall(t *testing.T) {
	calls := stubInstall(t, false, map[string]error{"uninstall": errors.New("does not exist")})

	// enforce.Default() is reached at the end of Uninstall; on a machine with no
	// browsers configured it has nothing to lift, which is what the empty config
	// here gives it.
	if err := Uninstall(policy.Config{}, "cfg.json"); err != nil {
		t.Fatalf("Uninstall with no service registered: %v", err)
	}
	for _, c := range *calls {
		if c == "uninstall" {
			t.Error("must not ask the SCM to remove a service that is not registered")
		}
	}
}
