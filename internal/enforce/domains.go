package enforce

import "github.com/codepurse/extension-guard/internal/policy"

// Domains blocks sites in every supported browser through its enterprise URL
// filter. It is a thin adapter over package policy, which owns the registry and
// managed-policy-file work; this type only states that blocking domains is one
// backend alongside locking extensions.
//
// It needs no new privilege and terminates no processes - it writes the same
// HKLM\SOFTWARE\Policies hive the extension lock already uses, which the tamper
// watcher is already watching. That is why this could ship without waiting on
// code signing, unlike blocking applications.
type Domains struct{}

// Name identifies this backend in logs and status output.
func (Domains) Name() string { return "domains" }

// Apply blocks every enabled domain and unblocks the rest.
func (Domains) Apply(cfg policy.Config) error { return policy.ApplyDomains(cfg) }

// Remove clears the guard's domain blocks, restoring the browsers.
func (Domains) Remove(cfg policy.Config) error { return policy.RemoveDomains(cfg) }

// Verify reports one status per supported browser: "enforced" means every domain
// that should be blocked right now is in that browser's filter.
func (d Domains) Verify(cfg policy.Config) []Status {
	browsers := policy.VerifyDomains(cfg)
	out := make([]Status, 0, len(browsers))
	for _, b := range browsers {
		out = append(out, Status{
			Enforcer: d.Name(),
			Target:   string(b.Kind),
			Present:  b.Installed,
			Enforced: b.Locked,
			Detail:   b.Detail,
		})
	}
	return out
}
