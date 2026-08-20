//go:build !windows

package policy

import "errors"

// Application blocking is Windows-only. The rule kinds are Windows concepts -
// Image File Execution Options, Store packages, window titles - and there is no
// honest way to map them onto another platform, so the entry points refuse rather
// than pretend.
//
// They refuse only when rules exist. A config with no apps returns nil, so the
// Linux port keeps applying extension and domain policy without an error on every
// cycle for a feature it was never asked to enforce.
var errAppsUnsupported = errors.New("blocking applications is only implemented on Windows")

// ApplyApps reports that app rules cannot be enforced here.
func ApplyApps(cfg Config) error {
	if !cfg.AnyApps() {
		return nil
	}
	return errAppsUnsupported
}

// SweepApps reports that app rules cannot be enforced here.
func SweepApps(cfg Config) error {
	if len(cfg.BlockedApps()) == 0 {
		return nil
	}
	return errAppsUnsupported
}

// VerifyApps reports every configured rule as unenforced, with the reason, rather
// than reporting nothing - a rule the user set up must not simply disappear from
// the status list.
func VerifyApps(cfg Config) []AppStatus {
	apps := cfg.BlockedApps()
	out := make([]AppStatus, 0, len(apps))
	for _, a := range apps {
		out = append(out, AppStatus{App: a, Detail: "not supported on this platform"})
	}
	return out
}

// RemoveApps has nothing to lift, since nothing was ever applied.
func RemoveApps(cfg Config) error { return nil }

// StoreApp is one installed Microsoft Store package. Declared here so callers
// (the status window's picker) compile everywhere.
type StoreApp struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

// InstalledStoreApps returns nothing off Windows.
func InstalledStoreApps() []StoreApp { return nil }
