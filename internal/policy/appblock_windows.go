//go:build windows

package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/codepurse/extension-guard/internal/activity"
)

// This file is the Windows half of application blocking. Two mechanisms, because
// neither covers the ground alone (see apps.go for the rule kinds):
//
//  1. A launch block, via Image File Execution Options. IFEO is the loader's
//     "run this under a debugger" hook: with a Debugger value set for an image
//     name, Windows starts the debugger instead of the program. Pointing it at
//     `guard blocked` means a blocked application never runs - the user gets a
//     message saying it is blocked, rather than watching it open and die.
//
//     IFEO is keyed on the executable's *file name*, with an optional full-path
//     filter, so it can express an exe rule and nothing else. It also only
//     applies where the loader consults it, which excludes Store apps (activated
//     through a broker).
//
//  2. A sweep, terminating anything running that matches any rule. This covers
//     all four kinds and needs no registry write at all, but it acts after the
//     process exists, so a blocked app appears briefly before it closes.
//
// Neither is a kernel-level block, and this file does not pretend otherwise:
// AppLocker needs Enterprise, Software Restriction Policies are absent from Home
// editions, and a filesystem filter driver needs an EV certificate and WHQL
// signing. What the guard has instead is a SYSTEM service, a watchdog, and a
// password gate - so a bypass has to survive continuous correction rather than
// just being applied once.
//
// One consequence worth stating: an IFEO key whose Debugger points at a guard.exe
// that has been deleted makes the application fail to launch with a loader error
// rather than a message. That fails closed, which is the right direction, and an
// authorized uninstall removes the keys (RemoveApps) so it does not outlive the
// guard.

// The launch-block registry location is reached through these vars rather than
// named directly, so the reconcile logic below can be exercised against a
// throwaway key under HKCU. A test must not write the real IFEO hive: it is
// machine-wide, it decides whether programs start, and a test that left an entry
// behind would block an application on the developer's machine.
var (
	ifeoHive = registry.LOCAL_MACHINE
	ifeoRoot = ifeoRootPath
)

const (
	// ifeoRootPath is the loader's per-image options key. It is deliberately outside
	// HKLM\SOFTWARE\Policies, which is the hive the tamper watcher watches, so a
	// deleted launch block is restored by the periodic re-apply rather than within
	// milliseconds. The sweep is what covers the gap: the app can start during that
	// window, and is closed about a second later.
	ifeoRootPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	// debuggerValue is the value the loader reads as "run this instead".
	debuggerValue = "Debugger"
	// useFilterValue switches a key from "every image with this name" to "only the
	// paths named by the filter subkeys below it".
	useFilterValue = "UseFilter"
	// filterPathValue is the full path one filter subkey applies to.
	filterPathValue = "FilterFullPath"
	// filterKeyPrefix marks the filter subkeys the guard owns. Anything under an
	// IFEO key that does not carry this prefix belongs to something else and is
	// left alone.
	filterKeyPrefix = "ExtensionGuard"
	// blockedSubcommand is the guard subcommand IFEO launches in place of a
	// blocked application; it shows the "this app is blocked" message and exits.
	blockedSubcommand = "blocked"
)

// storePackagesKey lists the installed Store packages for the current user. It is
// the per-user class registration, which a normal user can read - the machine-wide
// copy under HKLM is locked down, and the picker runs unprivileged.
const storePackagesKey = `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`

// ApplyApps reconciles application blocking with cfg: every enabled exe rule has
// its launch block in place, every launch block the guard owns and no longer
// wants is removed, and anything running that a rule blocks is terminated.
// Requires Administrator (it writes HKLM); the sweep alone needs only the right
// to terminate the target.
func ApplyApps(cfg Config) error {
	want := cfg.BlockedApps()

	var errs []string
	// The launch blocks are reconciled even when no rule is configured at all.
	// "The rule was deleted" and "there was never a rule" look identical from
	// here, and getting that wrong would leave an executable permanently unable to
	// start, blocked by a key nothing will ever come back to clean up. It costs one
	// enumeration of a key that has a few dozen entries.
	if err := syncLaunchBlocks(want); err != nil {
		errs = append(errs, fmt.Sprintf("launch blocks: %v", err))
	}
	if err := SweepApps(cfg); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// SweepApps terminates every running process that an enabled rule blocks. It is
// the half of enforcement that has to run continuously, so the service calls it
// on a fast ticker; it is safe to call as often as you like and does nothing when
// no rule is enabled.
func SweepApps(cfg Config) error {
	apps := cfg.BlockedApps()
	if len(apps) == 0 {
		return nil
	}
	procs, err := snapshotProcesses(NeedsPaths(apps), NeedsTitles(apps))
	if err != nil {
		return fmt.Errorf("list processes: %w", err)
	}
	self := uint32(os.Getpid())
	var errs []string
	for _, p := range BlockedProcesses(apps, procs) {
		// Belt and braces over the protected-image list: a rule must never be able
		// to make the guard terminate the guard.
		if p.PID == self {
			continue
		}
		if err := terminateProcess(p.PID); err != nil {
			errs = append(errs, fmt.Sprintf("%s (pid %d): %v", p.Name, p.PID, err))
			continue
		}
		recordClosed(apps, p)
	}
	if len(errs) > 0 {
		return fmt.Errorf("close blocked apps: %s", strings.Join(errs, "; "))
	}
	return nil
}

// SampleUsage reports which limited blocks are being used at this moment: in
// window, with at least one of the applications they cover running. The service
// calls it once a second and charges the elapsed time to whatever it names.
//
// It takes its own snapshot rather than sharing the sweep's. That is a second walk
// of the process list per second, which is worth stating plainly and then putting
// in proportion: it only happens when a limit is configured, it asks for image
// paths and window titles only when a limited rule is matched on them, and sharing
// the sweep's snapshot would mean threading a process list through the Sweeper
// interface so that one backend could hand it to a measurement that is not
// enforcement at all. Measuring is a separate job from enforcing, and it reads
// better as one.
func SampleUsage(cfg Config, at time.Time) ([]string, error) {
	measure, paths, titles := cfg.MeasurementNeeds(at)
	if !measure {
		return nil, nil
	}
	procs, err := snapshotProcesses(paths, titles)
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	return cfg.RunningLimited(at, procs), nil
}

// VerifyApps reports one status per enabled rule. Read-only, so the status window
// can call it without elevation.
func VerifyApps(cfg Config) []AppStatus {
	apps := cfg.BlockedApps()
	if len(apps) == 0 {
		return nil
	}
	procs, err := snapshotProcesses(NeedsPaths(apps), NeedsTitles(apps))
	if err != nil {
		procs = nil // report on what we can; a rule with no snapshot is not "running"
	}
	running := make(map[string]bool, len(apps))
	for _, p := range procs {
		for _, a := range apps {
			if a.Matches(p) {
				running[a.key()] = true
			}
		}
	}

	var installedStore map[string]bool
	out := make([]AppStatus, 0, len(apps))
	for _, a := range apps {
		f := appFacts{running: running[a.key()], present: true}
		switch a.Kind {
		case AppExe:
			f.launchApplies = true
			f.launchBlocked = launchBlocked(a.Value)
			// A bare image name says nothing about where - or whether - the executable
			// is installed, so "present" stays true: claiming it is absent would be a
			// statement the guard cannot make.
			if hasPathSep(a.Value) {
				f.present = fileExists(a.Value)
			}
		case AppFolder:
			f.present = dirExists(a.Value)
		case AppStore:
			if installedStore == nil {
				installedStore = installedStoreFamilies()
			}
			f.present = installedStore[strings.ToLower(a.Value)]
		}
		out = append(out, appStatus(a, f))
	}
	return out
}

// RemoveApps lifts every launch block the guard owns. Used on an authorized
// teardown; there is nothing to restore beyond that, since the sweep leaves no
// state behind - a blocked app simply runs again once nothing is sweeping.
func RemoveApps(cfg Config) error { return syncLaunchBlocks(nil) }

// --- launch blocks (IFEO) ----------------------------------------------------

// syncLaunchBlocks reconciles the IFEO keys so that afterwards:
//
//   - every enabled exe rule is blocked at launch,
//   - every launch block the guard owns and no longer wants is gone, including
//     one for a rule that was deleted from the config outright, and
//   - anything under IFEO the guard does not own is untouched, because another
//     tool (or a developer's own debugger setting) may legitimately be there.
//
// The last two are why this enumerates the whole IFEO key rather than working
// from the config's own "inactive" list: enforcement has to be reconciled, not
// appended to, and a rule that vanished from the config would otherwise stay
// blocked forever with nothing left to explain why.
func syncLaunchBlocks(want []App) error {
	cmd, err := guardCommand()
	if err != nil {
		return err
	}

	// Desired state per image name: blockAll when a bare-name rule covers every
	// copy, otherwise the specific paths to filter on.
	type intent struct {
		blockAll bool
		paths    []string
	}
	wanted := make(map[string]*intent)
	for _, a := range want {
		if a.Kind != AppExe {
			continue
		}
		name := strings.ToLower(baseName(a.Value))
		in := wanted[name]
		if in == nil {
			in = &intent{}
			wanted[name] = in
		}
		if hasPathSep(a.Value) {
			in.paths = append(in.paths, a.Value)
		} else {
			// A rule on the bare name is broader than any path rule for the same
			// name, so it wins: filtering would let the other copies through.
			in.blockAll = true
		}
	}

	var errs []string
	for name, in := range wanted {
		if err := writeLaunchBlock(name, in.blockAll, in.paths, cmd); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	// Everything of ours that is no longer wanted.
	for _, name := range ourLaunchBlocks() {
		if wanted[strings.ToLower(name)] != nil {
			continue
		}
		if err := clearLaunchBlock(name); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// writeLaunchBlock puts one image name into the desired state.
func writeLaunchBlock(name string, blockAll bool, paths []string, cmd string) error {
	path := ifeoRoot + `\` + name
	key, _, err := registry.CreateKey(ifeoHive, path, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()

	// A Debugger set by something else is not ours to overwrite. Refusing loudly
	// is better than silently disabling another tool's hook - and the sweep still
	// closes the app, so the rule is not lost.
	if cur, _, err := key.GetStringValue(debuggerValue); err == nil && cur != "" && !ourDebugger(cur) {
		return fmt.Errorf("another program already has a debugger set for this executable (%q)", cur)
	}

	if blockAll {
		// Block every copy: one unfiltered Debugger, and no filter of ours left
		// behind (with UseFilter set, the unfiltered Debugger is ignored).
		if err := key.SetStringValue(debuggerValue, cmd); err != nil {
			return err
		}
		if err := clearOurFilters(key, path, nil); err != nil {
			return err
		}
		return deleteOurValue(key, useFilterValue)
	}

	// Block only the named paths. UseFilter turns the key into "consult the filter
	// subkeys"; each subkey names one full path and the debugger to run for it.
	if err := deleteOurDebugger(key); err != nil {
		return err
	}
	if err := key.SetDWordValue(useFilterValue, 1); err != nil {
		return err
	}
	keep := make(map[string]bool, len(paths))
	for i, p := range paths {
		sub := filterKeyPrefix + strconv.Itoa(i+1)
		keep[strings.ToLower(sub)] = true
		if err := writeFilter(path+`\`+sub, p, cmd); err != nil {
			return err
		}
	}
	return clearOurFilters(key, path, keep)
}

func writeFilter(path, fullPath, cmd string) error {
	key, _, err := registry.CreateKey(ifeoHive, path, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := key.SetStringValue(filterPathValue, fullPath); err != nil {
		return err
	}
	return key.SetStringValue(debuggerValue, cmd)
}

// clearOurFilters removes the guard's filter subkeys under an IFEO key, keeping
// the ones named in keep. Subkeys without our prefix are left alone.
func clearOurFilters(key registry.Key, path string, keep map[string]bool) error {
	subs, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil // nothing readable underneath; nothing of ours to remove
	}
	for _, s := range subs {
		if !strings.HasPrefix(s, filterKeyPrefix) || keep[strings.ToLower(s)] {
			continue
		}
		if err := registry.DeleteKey(ifeoHive, path+`\`+s); err != nil {
			return err
		}
	}
	return nil
}

// clearLaunchBlock removes everything the guard put on one image name, and the
// key itself if that leaves it empty. An IFEO key we emptied but did not create
// is still ours to delete only when nothing else remains in it.
func clearLaunchBlock(name string) error {
	path := ifeoRoot + `\` + name
	key, err := registry.OpenKey(ifeoHive, path, registry.ALL_ACCESS)
	if err != nil {
		return nil // already gone
	}
	if err := deleteOurDebugger(key); err != nil {
		key.Close()
		return err
	}
	if err := clearOurFilters(key, path, nil); err != nil {
		key.Close()
		return err
	}
	if err := deleteOurValue(key, useFilterValue); err != nil {
		key.Close()
		return err
	}
	values, _ := key.ReadValueNames(-1)
	subs, _ := key.ReadSubKeyNames(-1)
	key.Close()
	if len(values) == 0 && len(subs) == 0 {
		_ = registry.DeleteKey(ifeoHive, path)
	}
	return nil
}

// deleteOurDebugger removes a Debugger value only when it is one we wrote.
func deleteOurDebugger(key registry.Key) error {
	cur, _, err := key.GetStringValue(debuggerValue)
	if err != nil || !ourDebugger(cur) {
		return nil
	}
	return deleteOurValue(key, debuggerValue)
}

func deleteOurValue(key registry.Key, name string) error {
	if err := key.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// ourLaunchBlocks lists the image names under IFEO that carry a launch block the
// guard wrote, either directly or through one of its filter subkeys.
func ourLaunchBlocks() []string {
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
	for _, n := range names {
		if ownedLaunchBlock(ifeoRoot + `\` + n) {
			out = append(out, n)
		}
	}
	return out
}

// ownedLaunchBlock reports whether an IFEO key holds a block the guard wrote.
func ownedLaunchBlock(path string) bool {
	key, err := registry.OpenKey(ifeoHive, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer key.Close()
	if v, _, err := key.GetStringValue(debuggerValue); err == nil && ourDebugger(v) {
		return true
	}
	subs, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return false
	}
	for _, s := range subs {
		if strings.HasPrefix(s, filterKeyPrefix) {
			return true
		}
	}
	return false
}

// launchBlocked reports whether an exe rule's launch block is currently in place.
// A bare-name rule needs the unfiltered Debugger; a path rule is satisfied either
// by a filter naming that path or by an unfiltered Debugger, which is broader.
func launchBlocked(value string) bool {
	path := ifeoRoot + `\` + baseName(value)
	key, err := registry.OpenKey(ifeoHive, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer key.Close()

	unfiltered := false
	if v, _, err := key.GetStringValue(debuggerValue); err == nil && ourDebugger(v) {
		unfiltered = true
	}
	if filter, _, err := key.GetIntegerValue(useFilterValue); err == nil && filter == 1 {
		// With UseFilter set the loader ignores the unfiltered Debugger, so only a
		// matching filter counts.
		unfiltered = false
	}
	if !hasPathSep(value) {
		return unfiltered
	}
	if unfiltered {
		return true
	}
	subs, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return false
	}
	for _, s := range subs {
		if !strings.HasPrefix(s, filterKeyPrefix) {
			continue
		}
		sub, err := registry.OpenKey(ifeoHive, path+`\`+s, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		fp, _, fpErr := sub.GetStringValue(filterPathValue)
		dbg, _, dbgErr := sub.GetStringValue(debuggerValue)
		sub.Close()
		if fpErr == nil && dbgErr == nil && samePath(fp, value) && ourDebugger(dbg) {
			return true
		}
	}
	return false
}

// guardCommand is what IFEO should run in place of a blocked application:
// guard.exe from this binary's own directory, with the "blocked" subcommand.
//
// It is derived from the running executable's directory rather than from a stored
// path so the status window computes the same command the service writes - both
// binaries are installed side by side - which is what lets an unprivileged verify
// recognize a launch block it did not create.
func guardCommand() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate this executable: %w", err)
	}
	return `"` + filepath.Join(filepath.Dir(exe), "guard.exe") + `" ` + blockedSubcommand, nil
}

// ourDebugger reports whether a Debugger value is one the guard wrote. It matches
// on shape rather than on an exact string so a reinstall into a different
// directory, or a differently-cased path, is still recognized as ours - while
// anything else keeps its hook.
func ourDebugger(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return strings.HasSuffix(s, " "+blockedSubcommand) && strings.Contains(s, "guard.exe")
}

// --- processes and windows ---------------------------------------------------

// snapshotProcesses lists the running processes. Image paths and window titles
// are only gathered when a rule needs them: the first costs a handle per process
// and the second a pass over every top-level window, and most block lists need
// neither.
func snapshotProcesses(withPaths, withTitles bool) ([]Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var titles map[uint32][]string
	if withTitles {
		titles = windowTitles()
	}

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []Process
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		p := Process{PID: e.ProcessID, Name: windows.UTF16ToString(e.ExeFile[:])}
		if withPaths && p.PID > 4 {
			p.Path = imagePath(p.PID)
		}
		if titles != nil {
			p.Titles = titles[p.PID]
		}
		out = append(out, p)
	}
	if err != nil && !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return out, err
	}
	return out, nil
}

// imagePath returns a process's full executable path, or "" when it cannot be
// read - which is not an error worth reporting: a process we cannot open is one
// we could not terminate either.
func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// terminateProcess closes one process. A process that has already exited is
// success, not failure: the sweep runs on a timer and races normal exits.
func terminateProcess(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil // gone between the snapshot and now
		}
		return err
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return err
	}
	return nil
}

var (
	procGetWindowTextW = windows.NewLazySystemDLL("user32.dll").NewProc("GetWindowTextW")

	// The EnumWindows callback is created once, at package level, and collects
	// into titleAcc under titleMu. syscall.NewCallback never releases a callback,
	// and the sweep runs about once a second - building a fresh closure each time
	// would exhaust the process's callback slots within the hour.
	titleMu            sync.Mutex
	titleAcc           map[uint32][]string
	enumWindowsAndText = syscall.NewCallback(collectWindowTitle)
)

func collectWindowTitle(hwnd windows.HWND, _ uintptr) uintptr {
	if windows.IsWindowVisible(hwnd) {
		if t := windowText(hwnd); t != "" {
			var pid uint32
			if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err == nil && pid != 0 {
				titleAcc[pid] = append(titleAcc[pid], t)
			}
		}
	}
	return 1 // keep enumerating
}

// windowTitles maps each process to the titles of the visible top-level windows
// it owns. Invisible windows are skipped: every process has a few, they are never
// what a person means by "that window", and matching them would close apps the
// user can see no reason to have closed.
func windowTitles() map[uint32][]string {
	titleMu.Lock()
	defer titleMu.Unlock()
	titleAcc = make(map[uint32][]string)
	_ = windows.EnumWindows(enumWindowsAndText, nil)
	out := titleAcc
	titleAcc = nil
	return out
}

func windowText(hwnd windows.HWND) string {
	buf := make([]uint16, 512)
	n, _, _ := procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// --- Microsoft Store packages -----------------------------------------------

// StoreApp is one installed Microsoft Store package, as the picker lists it.
type StoreApp struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

// frameworkMarkers identify packages that are libraries rather than apps. They
// are the bulk of what is installed and none of them is something a person wants
// to block, so the picker leaves them out.
var frameworkMarkers = []string{
	".framework", "vclibs", "runtime", "directx", "net.native", "ui.xaml",
	"windows.client", "windowsappruntime", "webexperience", "webview",
}

// InstalledStoreApps lists the Store apps installed for the current user, newest
// name first, one entry per package family (a family can have several versions
// and architectures installed at once).
//
// The list comes from the per-user package registration in the registry rather
// than from the AppX APIs or PowerShell: the picker runs in the status window,
// unprivileged, and must not take seconds to open.
func InstalledStoreApps() []StoreApp {
	key, err := registry.OpenKey(registry.CURRENT_USER, storePackagesKey, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool, len(names))
	var out []StoreApp
	for _, full := range names {
		fam, err := StoreFamily(full)
		if err != nil || seen[strings.ToLower(fam)] || isFrameworkPackage(full) {
			continue
		}
		seen[strings.ToLower(fam)] = true
		out = append(out, StoreApp{Family: fam, Name: storeDisplayName(key, full, fam)})
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// installedStoreFamilies is the same list reduced to a lookup, for Verify.
func installedStoreFamilies() map[string]bool {
	apps := InstalledStoreApps()
	out := make(map[string]bool, len(apps))
	for _, a := range apps {
		out[strings.ToLower(a.Family)] = true
	}
	return out
}

func isFrameworkPackage(fullName string) bool {
	n := strings.ToLower(fullName)
	for _, m := range frameworkMarkers {
		if strings.Contains(n, m) {
			return true
		}
	}
	return false
}

// storeDisplayName is the friendliest name available for a package. DisplayName
// is often an "ms-resource:" indirection that only the package's own resource
// bundle can resolve, so anything of that shape is discarded in favour of the
// package name itself, which at least reads as English.
func storeDisplayName(packages registry.Key, fullName, family string) string {
	if sub, err := registry.OpenKey(packages, fullName, registry.QUERY_VALUE); err == nil {
		name, _, err := sub.GetStringValue("DisplayName")
		sub.Close()
		if err == nil {
			n := sanitizeStoreName(name)
			if n != "" && !strings.HasPrefix(strings.ToLower(n), "ms-resource:") && !strings.HasPrefix(n, "@{") {
				return n
			}
		}
	}
	// Fall back to the package name: "Microsoft.WindowsCalculator_8wekyb..." reads
	// as "WindowsCalculator", which is enough to find in a list.
	name := family
	if i := strings.Index(name, "_"); i > 0 {
		name = name[:i]
	}
	if i := strings.LastIndex(name, "."); i >= 0 && i < len(name)-1 {
		name = name[i+1:]
	}
	return name
}

// sanitizeStoreName constrains a package's DisplayName before anything uses it.
//
// Unlike a label the user typed, this string comes from a per-user registry key
// that any standard user can write, and it travels into the status window and
// from there into the command line of an *elevated* guard.exe. Correct escaping
// is what makes that safe (see buildArgs in statusui), but a display name has no
// business containing quoting characters or control codes in the first place, and
// narrowing it here means one mistake at the boundary is not enough on its own.
// The length cap is for the same reason a name is not a paragraph.
func sanitizeStoreName(s string) string {
	const maxRunes = 96
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxRunes {
			break
		}
		switch {
		case r < 0x20, r == 0x7f: // control characters, including newlines
		case r == '"', r == '\\':
		default:
			b.WriteRune(r)
			n++
		}
	}
	return strings.TrimSpace(b.String())
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// appClosedThrottle is how often the same application being closed is written to
// the activity log. The sweep runs about once a second, so an application that
// relaunches itself - or one the guard cannot close and keeps trying - would
// otherwise write the same line sixty times a minute. A repeat inside this window
// is treated as the same event still happening rather than a new one.
const appClosedThrottle = 5 * time.Minute

// recordClosed notes a termination in the activity log, naming the rule that
// matched so the entry says why the application went away rather than only that
// it did.
//
// The rule is looked up a second time rather than threaded out of
// BlockedProcesses: this runs only for a process that was actually closed, which
// is rare, and it keeps that matcher's signature to the one thing it is for.
func recordClosed(apps []App, p Process) {
	detail := ""
	for _, a := range apps {
		if a.Matches(p) {
			if rule := a.Display(); !strings.EqualFold(rule, p.Name) {
				detail = "matched the rule for " + rule
			}
			break
		}
	}
	activity.RecordThrottled("closed|"+strings.ToLower(p.Name), appClosedThrottle, activity.Event{
		Kind:   activity.AppClosed,
		Target: p.Name,
		Detail: detail,
	})
}
