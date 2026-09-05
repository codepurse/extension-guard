//go:build windows

package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Blocking the browsers the guard cannot filter.
//
// A force-installed extension is installed in the browsers the guard writes
// policy for. A browser it writes no policy for carries none of them - so leaving
// such a browser runnable is leaving a way round every lock this program exists
// to hold. That is the hole this file closes, and it is the only reason this
// program blocks an executable at all.
//
// The mechanism is Image File Execution Options: the loader's "run this under a
// debugger" hook. With a Debugger value set for an image name, Windows starts the
// debugger instead of the program, so pointing it at `guard blocked` means the
// browser never runs and the person gets a message rather than watching a window
// open and vanish.
//
// What this is not: it is not a kernel-level block. AppLocker needs Enterprise,
// Software Restriction Policies are gone from Home editions, and a filesystem
// filter driver needs an EV certificate and WHQL signing. What the guard has
// instead is a SYSTEM service, a watchdog and a password gate - so getting round
// this has to survive continuous correction rather than merely being done once.
//
// Two consequences, stated rather than discovered:
//
//   - IFEO lives outside HKLM\SOFTWARE\Policies, which is the hive the tamper
//     watcher watches. A deleted block is restored by the periodic re-apply
//     rather than within milliseconds, so there is a window in which the browser
//     will start.
//   - A Debugger pointing at a guard.exe that has been deleted makes the browser
//     fail to launch with a loader error rather than a message. That fails
//     closed, which is the right direction, and an authorized uninstall removes
//     the keys so it cannot outlive the guard.

// The registry location is reached through these vars rather than named directly,
// so the reconcile logic can be exercised against a throwaway key under HKCU. A
// test must not write the real IFEO hive: it is machine-wide, it decides whether
// programs start, and a test that left an entry behind would stop a browser
// launching on the developer's machine.
var (
	ifeoHive = registry.LOCAL_MACHINE
	ifeoRoot = ifeoRootPath
)

const (
	ifeoRootPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	// debuggerValue is the value the loader reads as "run this instead".
	debuggerValue = "Debugger"
	// blockedSubcommand is the guard subcommand IFEO launches in place of a blocked
	// browser; it shows the message and exits.
	blockedSubcommand = "blocked"
)

// ApplyBrowserBlocks reconciles the launch blocks with cfg: every unsupported
// browser found on this machine is blocked when the setting is on, and every
// block the guard owns is cleared when it is off. Requires Administrator.
//
// It blocks by image name and every copy of it. A path filter would be more
// precise and is not wanted here: a second copy of Opera under a different
// directory is the same hole as the first, and the whole point is that no
// unfiltered browser runs.
func ApplyBrowserBlocks(cfg Config) error {
	var want []string
	if cfg.BlockUnsupported {
		for _, b := range UnmanagedBrowsers() {
			if name := strings.ToLower(strings.TrimSpace(b.Image())); name != "" {
				want = append(want, name)
			}
		}
	}
	return syncBrowserBlocks(want)
}

// RemoveBrowserBlocks clears every launch block the guard owns, whatever the
// config says. Used on an authorized teardown and at the start of a pause: a
// pause has to hand the browsers back, or protection being off would not be off.
func RemoveBrowserBlocks() error { return syncBrowserBlocks(nil) }

func syncBrowserBlocks(want []string) error {
	wanted := make(map[string]bool, len(want))
	for _, name := range want {
		wanted[name] = true
	}

	var errs []string
	if len(wanted) > 0 {
		cmd, err := guardCommand()
		if err != nil {
			return err
		}
		names := make([]string, 0, len(wanted))
		for name := range wanted {
			names = append(names, name)
		}
		// Sorted so a failure reports the same way twice and the log is readable.
		sort.Strings(names)
		for _, name := range names {
			if err := writeBrowserBlock(name, cmd); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			}
		}
	}
	// Everything of ours that is no longer wanted.
	for _, name := range ourBrowserBlocks() {
		if wanted[strings.ToLower(name)] {
			continue
		}
		if err := clearBrowserBlock(name); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// writeBrowserBlock puts one image name into the blocked state.
func writeBrowserBlock(name, cmd string) error {
	path := ifeoRoot + `\` + name
	key, _, err := registry.CreateKey(ifeoHive, path, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()

	// A Debugger set by something else is not ours to overwrite. Refusing loudly
	// beats silently disabling another tool's hook.
	if cur, _, err := key.GetStringValue(debuggerValue); err == nil && cur != "" && !ourDebugger(cur) {
		return fmt.Errorf("another program already has a debugger set for this executable (%q)", cur)
	}
	return key.SetStringValue(debuggerValue, cmd)
}

// clearBrowserBlock removes one block, and the key with it when nothing else is
// using it. Anything the guard did not write is left alone.
func clearBrowserBlock(name string) error {
	path := ifeoRoot + `\` + name
	key, err := registry.OpenKey(ifeoHive, path, registry.ALL_ACCESS)
	if err != nil {
		return nil // already gone
	}
	if cur, _, err := key.GetStringValue(debuggerValue); err == nil && ourDebugger(cur) {
		if err := key.DeleteValue(debuggerValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			key.Close()
			return err
		}
	}
	values, _ := key.ReadValueNames(-1)
	subs, _ := key.ReadSubKeyNames(-1)
	key.Close()
	// Only when the key is empty. IFEO keys are shared ground; another tool's
	// settings for the same image must survive our removal.
	if len(values) == 0 && len(subs) == 0 {
		_ = registry.DeleteKey(ifeoHive, path)
	}
	return nil
}

// ourBrowserBlocks lists the image names under IFEO carrying a block the guard
// wrote.
func ourBrowserBlocks() []string {
	root, err := registry.OpenKey(ifeoHive, ifeoRoot, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	var out []string
	for _, name := range names {
		key, err := registry.OpenKey(ifeoHive, ifeoRoot+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		cur, _, err := key.GetStringValue(debuggerValue)
		key.Close()
		if err == nil && ourDebugger(cur) {
			out = append(out, name)
		}
	}
	return out
}

// BrowserBlocked reports whether this image name currently carries a block the
// guard wrote. Read-only, so the status window can call it unprivileged.
func BrowserBlocked(image string) bool {
	image = strings.ToLower(strings.TrimSpace(image))
	if image == "" {
		return false
	}
	key, err := registry.OpenKey(ifeoHive, ifeoRoot+`\`+image, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	cur, _, err := key.GetStringValue(debuggerValue)
	return err == nil && ourDebugger(cur)
}

// guardCommand is what IFEO launches in place of a blocked browser.
func guardCommand() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate this executable: %w", err)
	}
	return `"` + filepath.Join(filepath.Dir(exe), "guard.exe") + `" ` + blockedSubcommand, nil
}

// ourDebugger reports whether a Debugger value is one the guard wrote. It matches
// on shape rather than on an exact string, so a reinstall into a different
// directory - or a differently-cased path - is still recognized as ours, while
// anything else keeps its hook.
func ourDebugger(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return strings.HasSuffix(s, " "+blockedSubcommand) && strings.Contains(s, "guard.exe")
}

// runningProc is one running process, reduced to what this program asks about.
type runningProc struct {
	Name string
	PID  uint32
}

// runningProcesses lists the running processes by image name and pid.
//
// It is the whole of what this program needs from the process list: whether a
// browser is running, so the window can say an extension change will not reach it
// until it restarts. There is no image-path lookup and no window enumeration,
// because nothing here matches on either - those cost a handle per process and a
// pass over every top-level window respectively, and this runs on a timer.
func runningProcesses() []runningProc {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return nil
	}
	var out []runningProc
	for {
		if name := windows.UTF16ToString(e.ExeFile[:]); name != "" {
			out = append(out, runningProc{Name: name, PID: e.ProcessID})
		}
		if err := windows.Process32Next(snap, &e); err != nil {
			return out
		}
	}
}

// runningImageNames is runningProcesses reduced to a set of lowercased names, for
// the callers that only ask "is this running".
func runningImageNames() map[string]bool {
	procs := runningProcesses()
	out := make(map[string]bool, len(procs))
	for _, p := range procs {
		out[strings.ToLower(p.Name)] = true
	}
	return out
}
