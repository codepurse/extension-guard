package enforce

import "github.com/codepurse/extension-guard/internal/policy"

// Apps keeps blocked applications closed. It is a thin adapter over package
// policy, which owns the Windows work; this type states that blocking
// applications is one backend alongside locking extensions and filtering sites.
//
// It differs from the other two in one way that matters to the service: the other
// backends write a policy the browser then honours by itself, so applying once is
// enough until something changes it. An application is not like that - a program
// the guard has not looked at yet is a program that is running. So Apps also
// implements Sweeper, and the service drives that on a fast ticker.
//
// This is also the backend that made code signing a prerequisite rather than a
// nicety: an unsigned service running as LocalSystem that terminates processes
// and writes launch-block registry keys is exactly the shape antivirus
// heuristics are built to quarantine.
type Apps struct{}

// Name identifies this backend in logs and status output.
func (Apps) Name() string { return "apps" }

// Apply puts every enabled rule's launch block in place, removes the ones no
// longer wanted, and closes anything running that a rule blocks.
func (Apps) Apply(cfg policy.Config) error { return policy.ApplyApps(cfg) }

// Sweep closes anything running that a rule blocks, and nothing else. It is the
// cheap half of Apply, safe to call every second.
func (Apps) Sweep(cfg policy.Config) error { return policy.SweepApps(cfg) }

// Remove lifts every launch block the guard owns. The sweep leaves no state to
// restore: a blocked app runs again as soon as nothing is sweeping.
func (Apps) Remove(cfg policy.Config) error { return policy.RemoveApps(cfg) }

// Verify reports one status per enabled rule. Target is the rule's display name,
// Present means the guard found it on this machine, and Enforced means the rule
// is holding right now - nothing matching it is running, and an executable rule
// also has its launch block in place.
func (a Apps) Verify(cfg policy.Config) []Status {
	apps := policy.VerifyApps(cfg)
	out := make([]Status, 0, len(apps))
	for _, s := range apps {
		out = append(out, Status{
			Enforcer: a.Name(),
			Target:   s.App.Display(),
			Present:  s.Present,
			Enforced: s.Enforced,
			Detail:   s.Detail,
		})
	}
	return out
}
