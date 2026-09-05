// Package enforce is the seam between "what the guard should enforce" and "how
// each kind of thing is enforced".
//
// Originally there was exactly one kind - browser extensions, locked via the
// enterprise force-install policy - and the service called into package policy
// directly. There are four now: extensions, the browser settings that decide
// whether locking an extension means anything (hardening), blocked sites, and
// blocked applications, with blocking sites outside the browser still to come.
// They share
// nothing with the registry writes that lock an extension except the lifecycle
// around them: apply on start, re-apply on tamper, verify for the status display,
// lift on an authorized teardown. This package names that lifecycle so a new
// backend plugs into the service rather than being threaded through it.
//
// One deliberate limitation: an Enforcer takes the whole policy.Config today
// rather than some narrower rule type. The config schema that describes blocks
// and schedules does not exist yet, and inventing an abstraction to fit it
// before it is designed would mean guessing. Each backend reads the part of the
// config it understands; the shape can tighten once there is a second
// implementation to check it against.
package enforce

import (
	"errors"

	"github.com/codepurse/extension-guard/internal/policy"
)

// Status is one enforcement fact, in terms general enough to describe any
// backend. For extensions, Target is a browser and Present means the browser is
// installed; for the planned app blocking, Target is an executable and Present
// means it was found on this machine. Enforced is the load-bearing field: it
// means the rule is currently applied and correct.
type Status struct {
	Enforcer string // which backend reported this ("extensions")
	Target   string // what it is about ("chrome")
	Present  bool   // the target exists on this machine
	Enforced bool   // the rule is applied and correct
	Detail   string // human-readable note: "ok", "missing", "partial (1/2)", ...
}

// Enforcer is one enforcement backend.
//
// Apply and Remove must be idempotent: the service calls Apply on every cycle -
// on startup, on tamper, and on a backstop timer - and relies on repeated calls
// being harmless. Verify must not change anything; it runs unprivileged from the
// status window.
type Enforcer interface {
	// Name identifies the backend in logs and status output.
	Name() string
	// Apply makes the machine match cfg.
	Apply(cfg policy.Config) error
	// Verify reports what is currently enforced, without changing anything.
	Verify(cfg policy.Config) []Status
	// Remove lifts everything this backend enforces, restoring the machine.
	Remove(cfg policy.Config) error
}

// Sweeper is an Enforcer whose rules need continuous attention rather than a
// policy written once. Blocking an application is the case: a browser honours a
// force-install policy by itself, but a program nobody has looked at yet is a
// program that is running.
//
// The service drives Sweep on a fast ticker, so an implementation must be cheap
// enough to run every second and must do nothing when the config asks for
// nothing. Announcing the need through an interface keeps the service ignorant of
// which backend has it.
type Sweeper interface {
	Sweep(cfg policy.Config) error
}

// Set is an ordered group of enforcers driven together.
type Set []Enforcer

// Default is the set the guard runs. New backends are added here.
func Default() Set { return Set{Extensions{}, Hardening{}, Browsers{}} }

// Apply applies every enforcer, joining any errors. It deliberately does not
// stop at the first failure: one backend failing (a browser policy key that
// needs rights we lack, say) must not silently leave the others unenforced.
func (s Set) Apply(cfg policy.Config) error {
	var errs []error
	for _, e := range s {
		if err := e.Apply(cfg); err != nil {
			errs = append(errs, wrap(e, "apply", err))
		}
	}
	return errors.Join(errs...)
}

// Remove lifts every enforcer, joining any errors. Same reasoning as Apply: a
// teardown that half-fails must report it rather than leave the machine locked
// with nothing left to manage the lock.
func (s Set) Remove(cfg policy.Config) error {
	var errs []error
	for _, e := range s {
		if err := e.Remove(cfg); err != nil {
			errs = append(errs, wrap(e, "remove", err))
		}
	}
	return errors.Join(errs...)
}

// Sweep runs the continuous half of enforcement: every member that implements
// Sweeper, in set order, with errors joined. Members that do not need it are
// skipped, so a set of policy-writing backends makes this a no-op.
func (s Set) Sweep(cfg policy.Config) error {
	var errs []error
	for _, e := range s {
		sw, ok := e.(Sweeper)
		if !ok {
			continue
		}
		if err := sw.Sweep(cfg); err != nil {
			errs = append(errs, wrap(e, "sweep", err))
		}
	}
	return errors.Join(errs...)
}

// Verify collects every enforcer's status, in set order.
func (s Set) Verify(cfg policy.Config) []Status {
	var out []Status
	for _, e := range s {
		out = append(out, e.Verify(cfg)...)
	}
	return out
}

// EnforcedCount is how many statuses report Enforced. The service compares this
// before and after a re-apply to decide whether anything actually needed fixing,
// so it can stay quiet in steady state.
func EnforcedCount(st []Status) int {
	n := 0
	for _, s := range st {
		if s.Enforced {
			n++
		}
	}
	return n
}

func wrap(e Enforcer, op string, err error) error {
	return errors.New(e.Name() + " " + op + ": " + err.Error())
}
