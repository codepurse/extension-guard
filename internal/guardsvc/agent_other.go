//go:build !windows

package guardsvc

// The session agent exists to evaluate window-title rules from the interactive
// user's session, because a Windows service cannot see that session's windows.
// Application blocking is Windows-only (see internal/policy/appblock_other.go),
// so off Windows there is nothing to spawn and these are no-ops.

type sessionAgent struct{}

func ensureSessionAgent(cur *sessionAgent, exe, configPath string) (*sessionAgent, error) {
	return nil, nil
}

func stopSessionAgent(a *sessionAgent) {}
