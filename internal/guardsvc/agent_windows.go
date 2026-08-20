//go:build windows

package guardsvc

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A Windows service runs in session 0, on its own window station. EnumWindows
// there enumerates the service desktop's windows - which is to say, none of the
// user's - so a window-title rule evaluated from the service would match nothing
// and silently enforce nothing. That is the worst kind of failure this project can
// ship: the user believes they are blocked and they are not.
//
// So when (and only when) a title rule is configured, the service starts a copy of
// itself in the interactive user's session - `guard agent` - which sweeps the
// title rules from where the windows actually are. Every other rule kind is
// matched on the process list, which is session-independent, and stays with the
// service, whose SYSTEM rights let it close processes the user cannot.
//
// The agent is deliberately the smaller half: it holds no password, writes no
// registry, and enforces only what needs a session to see.

// sessionAgent is a running agent process and the session it belongs to.
type sessionAgent struct {
	session uint32
	pid     uint32
	handle  windows.Handle
}

// alive reports whether the agent process is still running.
func (a *sessionAgent) alive() bool {
	if a == nil || a.handle == 0 {
		return false
	}
	ev, err := windows.WaitForSingleObject(a.handle, 0)
	return err == nil && ev == uint32(windows.WAIT_TIMEOUT)
}

// ensureSessionAgent returns an agent running in the console session, reusing cur
// when it is still the right one. It returns nil when nobody is logged on, which
// is not a failure: there are no windows to match, and the next call starts one
// once someone signs in.
//
// A session change (log off and back on, or switch user) invalidates the old
// agent, because its token and window station went with the old session.
func ensureSessionAgent(cur *sessionAgent, exe, configPath string) (*sessionAgent, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		// No session attached to the console (nobody signed in, or the console is
		// mid-transition).
		stopSessionAgent(cur)
		return nil, nil
	}
	if cur != nil && cur.session == session && cur.alive() {
		return cur, nil
	}
	stopSessionAgent(cur)
	return spawnInSession(session, exe, configPath)
}

// stopSessionAgent terminates the agent and releases its handle. Called when the
// service stops, and when the last title rule goes away.
func stopSessionAgent(a *sessionAgent) {
	if a == nil || a.handle == 0 {
		return
	}
	_ = windows.TerminateProcess(a.handle, 0)
	_ = windows.CloseHandle(a.handle)
	a.handle = 0
}

// spawnInSession starts `guard agent` as the user signed in to the given session.
//
// The desktop has to be named explicitly (winsta0\default): a process created
// from session 0 with no desktop lands on the service window station, which is
// exactly the blindness this whole file exists to avoid. The environment block is
// built from the user's token so the agent sees the user's own environment rather
// than SYSTEM's.
func spawnInSession(session uint32, exe, configPath string) (*sessionAgent, error) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(session, &token); err != nil {
		return nil, fmt.Errorf("no interactive user in session %d: %w", session, err)
	}
	defer token.Close()

	appName, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return nil, err
	}
	cmdLine, err := windows.UTF16PtrFromString(`"` + exe + `" -config "` + configPath + `" agent`)
	if err != nil {
		return nil, err
	}
	desktop, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return nil, err
	}
	dir, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return nil, err
	}

	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW)
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, token, false); err == nil {
		defer windows.DestroyEnvironmentBlock(env)
	} else {
		// Without a block the agent inherits SYSTEM's environment. It reads none of
		// it, so this is worth continuing over rather than failing on.
		env = nil
		flags &^= windows.CREATE_UNICODE_ENVIRONMENT
	}

	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, appName, cmdLine, nil, nil, false, flags, env, dir, &si, &pi); err != nil {
		return nil, fmt.Errorf("start session agent: %w", err)
	}
	_ = windows.CloseHandle(pi.Thread)
	return &sessionAgent{session: session, pid: pi.ProcessId, handle: pi.Process}, nil
}
