package enforce

import "github.com/codepurse/extension-guard/internal/policy"

// Browsers blocks the browsers the guard cannot filter.
//
// It is here for one reason, and it is the same reason Hardening is: a
// force-installed extension is only installed in the browsers the guard writes
// policy for. A browser it writes no policy for carries none of them, so leaving
// one runnable is leaving a way round every lock this program exists to hold.
// Blocking it is not a second feature bolted on - it is the extension lock being
// true rather than nearly true.
//
// It sits last in the set deliberately. The two backends before it establish the
// lock and close the hole inside the browsers being managed; this one closes the
// hole beside them, and reading the set top to bottom should reach the lock before
// the things that make it hold.
type Browsers struct{}

// Name identifies this backend in logs and status output.
func (Browsers) Name() string { return "browsers" }

// Apply blocks every unsupported browser found here, or clears the blocks when the
// setting is off.
func (Browsers) Apply(cfg policy.Config) error { return policy.ApplyBrowserBlocks(cfg) }

// Remove lifts the blocks. This runs on an authorized teardown and at the start of
// a pause, and the pause case is the one that matters: protection being off has to
// mean the browser opens again, or a pause would be leaving something enforced.
func (Browsers) Remove(policy.Config) error { return policy.RemoveBrowserBlocks() }

// Verify reports one status per unsupported browser found on this machine.
//
// A machine with no unsupported browser reports nothing, which is the honest
// answer: there is no hole to close and no rule to check. The status window says
// so in words rather than showing an empty table.
func (b Browsers) Verify(cfg policy.Config) []Status {
	found := policy.UnmanagedBrowsers()
	out := make([]Status, 0, len(found))
	for _, browser := range found {
		blocked := policy.BrowserBlocked(browser.Image())
		detail := "not blocked"
		switch {
		case blocked:
			detail = "blocked"
		case !cfg.BlockUnsupported:
			detail = "not blocked - the setting is off"
		}
		out = append(out, Status{
			Enforcer: b.Name(),
			Target:   browser.Image(),
			Present:  true,
			Enforced: blocked,
			Detail:   detail,
		})
	}
	return out
}
