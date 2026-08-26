package enforce

import "github.com/codepurse/extension-guard/internal/policy"

// Hardening pins the browser settings that decide whether the other backends
// mean anything. It is a thin adapter over package policy, which owns the
// registry and managed-policy-file work.
//
// It sits after Extensions in the set deliberately, even though nothing here
// depends on ordering: the hole it closes is a hole in *that* backend's promise -
// a force-installed extension does not run in a private window - so reading the
// set top to bottom should reach the lock before the thing that makes the lock
// hold.
//
// Like Domains and unlike Apps, it writes nothing but policy values under
// HKLM\SOFTWARE\Policies and terminates no processes, so the tamper watcher
// already covers it and it needs no new privilege.
type Hardening struct{}

// Name identifies this backend in logs and status output.
func (Hardening) Name() string { return "hardening" }

// Apply writes the settings for every knob that is on and clears the rest.
func (Hardening) Apply(cfg policy.Config) error { return policy.ApplyHardening(cfg) }

// Remove hands the settings back. This runs on an authorized teardown and at the
// start of a pause, and the pause case is the one that matters: protection being
// off has to mean private browsing works again, or a pause would be leaving
// something enforced.
func (Hardening) Remove(cfg policy.Config) error { return policy.RemoveHardening(cfg) }

// Verify reports one status per supported browser. "not configured" means no knob
// is on; "not available in firefox" means a knob is on that Firefox has no policy
// for, which is a different thing and has to read differently.
func (h Hardening) Verify(cfg policy.Config) []Status {
	browsers := policy.VerifyHardening(cfg)
	out := make([]Status, 0, len(browsers))
	for _, b := range browsers {
		out = append(out, Status{
			Enforcer: h.Name(),
			Target:   string(b.Kind),
			Present:  b.Installed,
			Enforced: b.Locked,
			Detail:   b.Detail,
		})
	}
	return out
}
