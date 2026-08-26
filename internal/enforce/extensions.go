package enforce

import "github.com/codepurse/extension-guard/internal/policy"

// Extensions enforces the browser "force-install" policy that locks the
// configured extensions in place. It is a thin adapter over package policy,
// which still owns the registry and managed-policy-file work; this type only
// states that locking extensions is one backend among several.
type Extensions struct{}

// Name identifies this backend in logs and status output.
func (Extensions) Name() string { return "extensions" }

// Apply writes the force-install policy for every enabled extension.
func (Extensions) Apply(cfg policy.Config) error { return policy.Apply(cfg) }

// Remove lifts the force-install lock, restoring the browsers.
func (Extensions) Remove(cfg policy.Config) error { return policy.Remove(cfg) }

// Verify reports one status per supported browser. It maps policy's
// browser-specific vocabulary onto the general one: a browser being installed is
// "present", and its lock being correct for every configured extension is
// "enforced".
func (e Extensions) Verify(cfg policy.Config) []Status {
	browsers := policy.Verify(cfg)
	out := make([]Status, 0, len(browsers))
	for _, b := range browsers {
		out = append(out, Status{
			Enforcer: e.Name(),
			Target:   string(b.Kind),
			Present:  b.Installed,
			Enforced: b.Locked,
			Detail:   b.Detail,
		})
	}
	return out
}
