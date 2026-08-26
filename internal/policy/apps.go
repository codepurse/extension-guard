package policy

import (
	"fmt"
	"os"
	"strings"
)

// This file adds blocked applications: games and other programs the guard keeps
// closed, alongside the extensions it locks and the sites it filters.
//
// Four kinds of rule, because "the app I want gone" is not one thing:
//
//   - "exe" is one executable, either a full path (what the file picker gives)
//     or a bare name like "steam.exe" (what a person types). A path blocks that
//     copy; a bare name blocks it wherever it lives.
//   - "folder" is every executable under a directory. Games install into their
//     own folder and ship several launchers, so naming the folder survives an
//     update that renames the binary.
//   - "store" is a Microsoft Store (AppX) package, identified by its package
//     family name. Store apps launch out of a versioned directory under
//     \WindowsApps, so a path rule would break on the next update; the family
//     name does not change.
//   - "title" is a window title substring. It is the escape hatch for the two
//     cases the others miss: an app that relocates its executable, and one
//     window of an app whose other windows are fine.
//
// How they are enforced is deliberately split across two mechanisms, because
// neither one covers the ground alone - see appblock_windows.go:
//
//   - A launch block (Image File Execution Options) stops an "exe" rule from
//     starting at all, which is the only way to avoid the app appearing on
//     screen before it dies. It is keyed on the executable's file name, so it
//     cannot express a folder, a Store package, or a window title.
//   - A sweep terminates anything already running that matches any rule. It
//     covers all four kinds and needs no registry write, but it acts after the
//     process exists, so a blocked app flickers before it closes.
//
// What this does not cover, stated plainly: it does not stop you *browsing* a
// blocked folder, and it is not a kernel-level block - a local administrator can
// stop the service, and while it is stopped nothing is swept. What it buys is the
// same bar the rest of the guard holds: tampering has to survive continuous
// correction by a SYSTEM service rather than sticking the moment it is done.

// The kinds of app rule. The zero value of App.Kind is treated as AppExe, so a
// hand-written rule that names only a value still means what its author meant.
const (
	AppExe    = "exe"
	AppFolder = "folder"
	AppStore  = "store"
	AppTitle  = "title"
)

// App is one blocked application. Value's meaning depends on Kind: an executable
// path or name, a folder, a Store package family name, or a window title
// substring. Label is the friendly name shown in the status window (it falls
// back to Value). Disabled keeps the rule in the list but stops enforcing it,
// exactly as it does for an extension or a domain.
type App struct {
	Kind     string `json:"kind"`
	Value    string `json:"value"`
	Label    string `json:"label,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	// Source records where the rule came from - "category:social" for one a
	// category added, empty for one a person added by hand. It is provenance and
	// nothing else: the sweep never reads it, so a wrong value cannot change what
	// is enforced. It exists so the status window can group a list of forty rules
	// into the four categories that produced them, and so a future
	// refresh-category knows which entries it owns and may top up.
	//
	// omitempty for the reason every field added since v1 carries it: a config
	// written before categories existed must still encode byte-identically, or
	// every trusted copy on disk fails its integrity check on upgrade.
	Source string `json:"source,omitempty"`
}

// maxAppEntries caps the list. Unlike the browser policies there is no external
// limit to respect here; the cost is our own. Every rule is compared against
// every running process on every sweep, and the sweep runs about once a second,
// so an unbounded list would quietly turn into a background CPU load. Two
// hundred is far more than any real block list and cheap to walk.
const maxAppEntries = 200

// protectedImages are executables the guard refuses to block or terminate, at
// any point, for any rule. Killing one of these does not inconvenience the user,
// it breaks the machine - explorer.exe takes the desktop away, lsass.exe or
// csrss.exe force a reboot, and terminating our own binaries would disarm the
// guard from inside a rule.
//
// This list is checked twice on purpose: once when a rule is added, so the user
// is told no rather than discovering it later, and again in the sweep, so a rule
// that reached the config some other way still cannot fire. A guardrail that
// only exists at the input is not a guardrail.
var protectedImages = map[string]bool{
	"system": true, "registry": true, "memory compression": true,
	"smss.exe": true, "csrss.exe": true, "wininit.exe": true, "winlogon.exe": true,
	"services.exe": true, "lsass.exe": true, "lsaiso.exe": true, "svchost.exe": true,
	"explorer.exe": true, "dwm.exe": true, "fontdrvhost.exe": true, "sihost.exe": true,
	"ctfmon.exe": true, "taskhostw.exe": true, "runtimebroker.exe": true,
	"userinit.exe": true, "logonui.exe": true, "consent.exe": true, "dllhost.exe": true,
	"conhost.exe": true, "wudfhost.exe": true, "spoolsv.exe": true, "audiodg.exe": true,
	"searchindexer.exe": true, "searchhost.exe": true, "startmenuexperiencehost.exe": true,
	"shellexperiencehost.exe": true, "sppsvc.exe": true, "trustedinstaller.exe": true,
	"wmiprvse.exe": true, "msmpeng.exe": true, "nissrv.exe": true,
	"securityhealthservice.exe": true, "securityhealthsystray.exe": true,
	"guard.exe": true, "extension-guard-status.exe": true,
}

// genericImages are file names too common to stand for one application. A bare
// name rule matches that name wherever it lives and, for "exe" rules, also
// becomes an Image File Execution Options entry keyed on the name alone - so
// blocking "client.exe" registers the guard as the debugger for every program
// that ships a client.exe, and blocking "launcher.exe" does the same. The user
// wanted one app gone and took out an unrelated set of them.
//
// This is not protectedImages, and it is deliberately enforced in a weaker place.
// protectedImages is checked again in the sweep, because a rule that would
// terminate lsass.exe must never fire however it reached the config. This one is
// checked only where a rule is *added*, and Validate accepts a config that
// already holds one.
//
// The difference is what a late check would cost. Validate runs on every
// enforcement pass, so refusing a generic name there would make an existing
// config with "launcher.exe" in it stop validating on upgrade - and a config
// that fails to validate has its whole schedule ignored. Somebody who wrote one
// broad rule a year ago would find every block they had scheduled quietly
// enforcing around the clock. A rule already in the config was put there on
// purpose and can be edited out; refusing to load it helps nobody.
//
// Nothing here is refused outright, either. The full path is still accepted, and
// so is a folder rule, because both name one program unambiguously. Only the
// bare name is refused.
//
// Real examples of each: Google Play Games launches client.exe, the Rockstar
// Games Launcher launches Launcher.exe, and Minecraft Java runs as javaw.exe.
// The scripting hosts at the end are here for a different reason - they are how
// a great deal of ordinary software starts, so a bare-name rule on one of them
// breaks the machine in ways that look like a hardware fault. cmd.exe,
// powershell.exe and pwsh.exe are deliberately absent: someone blocking the
// terminal by name means the terminal, and that is a rule worth allowing.
var genericImages = map[string]bool{
	"launcher.exe": true, "client.exe": true, "game.exe": true, "app.exe": true,
	"main.exe": true, "run.exe": true, "start.exe": true, "bin.exe": true,
	"setup.exe": true, "install.exe": true, "installer.exe": true,
	"update.exe": true, "updater.exe": true, "helper.exe": true,
	"service.exe": true, "server.exe": true, "bootstrapper.exe": true,
	"java.exe": true, "javaw.exe": true, "python.exe": true, "pythonw.exe": true,
	"node.exe": true, "electron.exe": true, "mono.exe": true,
	"wscript.exe": true, "cscript.exe": true,
	"rundll32.exe": true, "regsvr32.exe": true, "mshta.exe": true,
}

// GenericImage reports whether an image name is too common to be blocked by name
// alone. The name is compared case-insensitively.
func GenericImage(name string) bool {
	return genericImages[strings.ToLower(strings.TrimSpace(baseName(name)))]
}

// ProtectedImage reports whether an image name is one the guard will never block
// or terminate. The name is compared case-insensitively, and a full path is
// reduced to its file name first, so both "C:\Windows\explorer.exe" and
// "Explorer.EXE" are caught.
func ProtectedImage(name string) bool {
	return protectedImages[strings.ToLower(baseName(normalizeWinPath(name)))]
}

// systemRootDir is the Windows directory, used to refuse folder rules that would
// take the operating system out. It is a var so tests do not depend on the
// machine they run on.
var systemRootDir = defaultSystemRoot()

func defaultSystemRoot() string {
	for _, env := range []string{"SystemRoot", "WINDIR", "windir"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return normalizeWinPath(v)
		}
	}
	return `C:\Windows`
}

// NormalizeApp reduces what a person (or a file picker) supplies to the stored
// form of a rule, and refuses what cannot work or must not be allowed. Kind
// empty means "exe", so the common case needs no ceremony.
func NormalizeApp(kind, value, label string) (App, error) {
	k := strings.ToLower(strings.TrimSpace(kind))
	if k == "" {
		k = AppExe
	}
	// Explorer's "Copy as path" wraps the path in quotes, and pasting that is the
	// obvious way to fill this in by hand.
	v := strings.TrimSpace(strings.Trim(strings.TrimSpace(value), `"`))
	if v == "" {
		return App{}, fmt.Errorf("nothing to block - give an application, folder, Store app or window title")
	}
	out := App{Kind: k, Label: strings.TrimSpace(label)}

	switch k {
	case AppExe:
		p := normalizeWinPath(v)
		name := baseName(p)
		if name == "" {
			return App{}, fmt.Errorf("%q has no file name", value)
		}
		// A bare "steam" means steam.exe; nobody types the extension when naming an
		// app, and a rule with no extension would match no process.
		if !strings.Contains(name, ".") {
			p += ".exe"
			name += ".exe"
		}
		if !strings.EqualFold(extension(name), ".exe") {
			return App{}, fmt.Errorf("%q is not an .exe - block an application by its executable, or use a window title", value)
		}
		if ProtectedImage(name) {
			return App{}, fmt.Errorf("%s is part of Windows and cannot be blocked", name)
		}
		if hasPathSep(p) && !isAbsWinPath(p) {
			return App{}, fmt.Errorf("%q is a partial path - give the full path, or just %q to block it wherever it is", value, name)
		}
		out.Value = p
	case AppFolder:
		p := trimTrailingSep(normalizeWinPath(v))
		if !isAbsWinPath(p) {
			return App{}, fmt.Errorf(`%q is not a full folder path (e.g. C:\Games\Steam)`, value)
		}
		if isRootPath(p) {
			return App{}, fmt.Errorf("%q is a whole drive - blocking every program on it would take the machine out; name a folder inside it", value)
		}
		if bad, ok := criticalFolder(p); ok {
			return App{}, fmt.Errorf("%q covers %s, which Windows needs; name a folder outside it", value, bad)
		}
		out.Value = p
	case AppStore:
		fam, err := StoreFamily(v)
		if err != nil {
			return App{}, err
		}
		out.Value = fam
	case AppTitle:
		// A one- or two-character substring matches almost every window on the
		// machine, and the sweep terminates whatever owns a match. Refusing it is
		// cheaper than explaining why everything closed.
		if len([]rune(v)) < 3 {
			return App{}, fmt.Errorf("a window title needs at least 3 characters, otherwise it matches almost every window")
		}
		out.Value = v
	default:
		return App{}, fmt.Errorf("unknown kind %q - want exe, folder, store or title", kind)
	}
	return out, nil
}

// criticalFolder reports the operating-system directory a folder rule would take
// with it, and whether it does. Both directions matter: naming C:\Windows blocks
// the system directly, and naming a parent of it - or C:\Windows\System32, which
// is inside it - does the same by inclusion.
func criticalFolder(dir string) (string, bool) {
	root := systemRootDir
	if samePath(dir, root) || underFolder(dir, root) || underFolder(root, dir) {
		return root, true
	}
	return "", false
}

// StoreFamily reduces a Microsoft Store package identifier to its package family
// name, which is the part that survives an update.
//
// A package *full* name looks like "Microsoft.WindowsCalculator_11.2.2.0_x64__8wekyb3d8bbwe":
// name, version, architecture, an empty field, publisher id. The family name is
// the first and last of those joined - "Microsoft.WindowsCalculator_8wekyb3d8bbwe" -
// and it is what the versioned install directory under \WindowsApps reduces to,
// so it is what the sweep can still match after an update bumps the version.
func StoreFamily(s string) (string, error) {
	v := strings.Trim(strings.TrimSpace(s), `"`)
	if v == "" {
		return "", fmt.Errorf("empty Store app")
	}
	if i := strings.Index(v, "__"); i > 0 {
		name, pub := v[:i], v[i+2:]
		if j := strings.Index(name, "_"); j > 0 {
			name = name[:j] // drop version and architecture
		}
		if name == "" || pub == "" || strings.Contains(pub, "_") {
			return "", fmt.Errorf("%q is not a Store package name", s)
		}
		return name + "_" + pub, nil
	}
	// Already a family name: exactly one underscore, both halves non-empty.
	if i := strings.Index(v, "_"); i > 0 && i < len(v)-1 && !strings.Contains(v[i+1:], "_") {
		return v, nil
	}
	return "", fmt.Errorf("%q is not a Store package family name (they look like Microsoft.WindowsCalculator_8wekyb3d8bbwe)", s)
}

// StoreFamilyFromPath returns the package family name of an executable running
// out of a Store install, or "" when the path is not one. Store apps live in
// %ProgramFiles%\WindowsApps\<package full name>\, so the family name comes from
// the directory rather than from any API.
func StoreFamilyFromPath(path string) string {
	p := normalizeWinPath(path)
	const marker = `\windowsapps\`
	i := strings.Index(strings.ToLower(p), marker)
	if i < 0 {
		return ""
	}
	rest := p[i+len(marker):]
	if j := strings.Index(rest, `\`); j >= 0 {
		rest = rest[:j]
	}
	fam, err := StoreFamily(rest)
	if err != nil {
		return ""
	}
	return fam
}

// Process is one running program as the app blocker sees it. Path is empty when
// the image path could not be read (a process owned by an account with tighter
// rights than ours), and Titles holds the visible window titles it owns, which
// is only gathered when a title rule exists to need them.
type Process struct {
	PID    uint32
	Name   string
	Path   string
	Titles []string
	// OriginalName is the file name compiled into the executable's version
	// resource - what its author called it - which is not changed by renaming the
	// file on disk. It is gathered only when a bare-name rule exists to need it,
	// for the same reason Titles is: it costs a read of every running image.
	//
	// This is the answer to the cheapest bypass there is. A bare-name rule and the
	// launch block behind it are both keyed on the file's name, so renaming
	// opera.exe to chess.exe walks out of both, needs no privilege, and - unlike
	// every other way around the guard - is not corrected by anything, because
	// there is no policy key to put back. Matching the name its author gave it
	// means the rename has to go deeper than the file system to work.
	OriginalName string
}

// Matches reports whether a process is what this rule blocks.
func (a App) Matches(p Process) bool {
	switch a.Kind {
	case "", AppExe:
		if hasPathSep(a.Value) {
			// A rule naming a full path means that copy. Renaming the file makes it
			// a different path, and treating it as the same one would quietly widen
			// a rule the user deliberately narrowed - the bare-name form is how you
			// say "this program, wherever it is".
			return samePath(a.Value, p.Path)
		}
		return a.matchesImageName(p)
	case AppFolder:
		return underFolder(a.Value, p.Path)
	case AppStore:
		fam := StoreFamilyFromPath(p.Path)
		return fam != "" && strings.EqualFold(fam, a.Value)
	case AppTitle:
		needle := strings.ToLower(a.Value)
		for _, t := range p.Titles {
			if strings.Contains(strings.ToLower(t), needle) {
				return true
			}
		}
	}
	return false
}

// matchesImageName answers a bare-name exe rule against a process, by the name on
// disk and by the name compiled into the executable. See Process.OriginalName for
// why the second one is here.
//
// The compiled-in name is only ever consulted, never required: a process whose
// version resource could not be read - or which never had one, as plenty of
// legitimate software does not - is matched on its file name exactly as before. A
// rule that stopped working because a resource was missing would be a worse bug
// than the one this closes.
func (a App) matchesImageName(p Process) bool {
	if strings.EqualFold(a.Value, baseName(normalizeWinPath(p.Name))) {
		return true
	}
	orig := p.OriginalImage()
	return orig != "" && strings.EqualFold(a.Value, orig)
}

// OriginalImage is OriginalName reduced to the executable it actually names.
//
// The reduction that matters is the ".mui" suffix. Windows' own binaries keep
// their localized strings in a side-by-side resource file - notepad.exe's live in
// en-US\notepad.exe.mui - and the version reader follows that transparently, so
// asking notepad.exe for its compiled-in name answers "NOTEPAD.EXE.MUI". Left
// alone that would mean the protected-image list never recognized a single Windows
// binary by its compiled-in name, which is the one class of process the list
// exists for. Third-party software embeds its resource directly and is unaffected.
//
// The suffix is only dropped when what is left is still an executable, so this
// cannot quietly rewrite a name that genuinely ends that way.
func (p Process) OriginalImage() string {
	n := baseName(normalizeWinPath(strings.TrimSpace(p.OriginalName)))
	if trimmed, ok := trimSuffixFold(n, ".mui"); ok && hasSuffixFold(trimmed, ".exe") {
		return trimmed
	}
	return n
}

func trimSuffixFold(s, suffix string) (string, bool) {
	if hasSuffixFold(s, suffix) {
		return s[:len(s)-len(suffix)], true
	}
	return s, false
}

func hasSuffixFold(s, suffix string) bool {
	return len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix)
}

// SnapshotNeeds says what a process snapshot has to gather. Each field costs
// something per process per sweep, and the sweep runs about once a second, so
// nothing is collected because it might be useful.
//
// It is a struct rather than a run of bools because there are three of them now
// and they are passed together through two layers; four positional booleans is how
// a caller ends up silently asking for titles when it meant paths.
type SnapshotNeeds struct {
	// Paths requires opening every process to read its image path.
	Paths bool
	// Titles requires a pass over every top-level window in the session, and only
	// works from a process that has a desktop - see the session agent.
	Titles bool
	// Originals requires reading the version resource of every running image.
	// Implies Paths, since a resource is read from the file the path names.
	Originals bool
}

// SnapshotNeedsFor works out what a set of rules actually has to be matched on.
func SnapshotNeedsFor(apps []App) SnapshotNeeds {
	return SnapshotNeeds{
		Paths:     NeedsPaths(apps),
		Titles:    NeedsTitles(apps),
		Originals: NeedsOriginalNames(apps),
	}
}

// Or combines two sets of needs, for a caller collecting them across several
// groups of rules.
func (n SnapshotNeeds) Or(o SnapshotNeeds) SnapshotNeeds {
	return SnapshotNeeds{
		Paths:     n.Paths || o.Paths,
		Titles:    n.Titles || o.Titles,
		Originals: n.Originals || o.Originals,
	}
}

// WantPaths reports whether the snapshot has to read image paths, which reading
// version resources also requires.
func (n SnapshotNeeds) WantPaths() bool { return n.Paths || n.Originals }

// NeedsOriginalNames reports whether any rule is matched on a bare executable
// name - the one kind of rule a rename defeats, and so the only kind that needs
// the name compiled into the executable.
//
// A full-path rule does not need it (renaming makes it a different path, which is
// a different rule), and neither do folder, Store or title rules, which are not
// keyed on the file's name at all.
func NeedsOriginalNames(apps []App) bool {
	for _, a := range apps {
		switch a.Kind {
		case "", AppExe:
			if !hasPathSep(a.Value) {
				return true
			}
		}
	}
	return false
}

// NeedsTitles reports whether any of these rules is matched on window titles.
// Enumerating windows costs a pass over every top-level window in the session,
// so the sweep only does it when a rule needs it.
func NeedsTitles(apps []App) bool {
	for _, a := range apps {
		if a.Kind == AppTitle {
			return true
		}
	}
	return false
}

// NeedsPaths reports whether any of these rules is matched on the image path.
// Reading a process's full path means opening a handle per process, so the sweep
// skips it when every rule is a bare executable name or a window title.
func NeedsPaths(apps []App) bool {
	for _, a := range apps {
		switch a.Kind {
		case AppFolder, AppStore:
			return true
		case "", AppExe:
			if hasPathSep(a.Value) {
				return true
			}
		}
	}
	return false
}

// BlockedProcesses returns the running processes that one of these rules blocks
// and that the guard is willing to terminate. Protected images are dropped here
// rather than at the call site, so every caller inherits the guardrail.
func BlockedProcesses(apps []App, procs []Process) []Process {
	var out []Process
	for _, p := range procs {
		// PIDs 0 and 4 are the idle process and the kernel; there is nothing there
		// to terminate and asking is meaningless.
		//
		// The protected list is checked against all three names a process has. The
		// compiled-in one is in here because matching gained it: a rule that can
		// now fire on a version resource must be refusable on one too, or the
		// guardrail would cover one of the two ways to reach lsass.exe. A rule
		// naming a system image is refused when it is added, so this is the second
		// of the two checks the protected list has always had - it just has one
		// more name to check now.
		if p.PID <= 4 || anyProtected(p) {
			continue
		}
		for _, a := range apps {
			if a.Matches(p) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// anyProtected reports whether a process is one the guard must never terminate,
// under any of the names it goes by: the name on disk, its full path, and the name
// its author compiled into it.
func anyProtected(p Process) bool {
	if ProtectedImage(p.Name) {
		return true
	}
	if p.Path != "" && ProtectedImage(p.Path) {
		return true
	}
	orig := p.OriginalImage()
	return orig != "" && ProtectedImage(orig)
}

// AppStatus is one rule's enforcement state, as `guard verify` and the status
// window report it.
type AppStatus struct {
	App      App
	Present  bool // the target was found on this machine
	Enforced bool // the rule is holding right now
	Detail   string
}

// appFacts is what a platform can observe about one rule. Turning facts into a
// status here means Windows and every other platform describe a rule identically.
type appFacts struct {
	present bool // the executable, folder or package exists on this machine
	running bool // something the rule matches is running right now
	// launchApplies is whether this kind of rule has a launch block at all;
	// launchBlocked is whether that block is currently in place.
	launchApplies bool
	launchBlocked bool
}

func appStatus(a App, f appFacts) AppStatus {
	s := AppStatus{App: a, Present: f.present}
	switch {
	case f.running:
		// Not a fault to hide: the sweep closes it within about a second, and until
		// it does, the honest answer is that the app is up.
		s.Detail = "a blocked app is running - closing it"
	case f.launchApplies && !f.launchBlocked:
		s.Detail = "launch block missing"
	case !f.present:
		s.Enforced, s.Detail = true, "not on this machine"
	default:
		s.Enforced, s.Detail = true, "blocked"
	}
	return s
}

// Display is the rule's friendly name: its label when it has one, otherwise the
// value itself.
func (a App) Display() string {
	if l := strings.TrimSpace(a.Label); l != "" {
		return l
	}
	return a.Value
}

// Summary says what a rule actually covers, which the value alone does not: a
// folder covers its contents, a bare executable name covers every copy on the
// machine, and a title covers whatever happens to show it. Both the CLI listing
// and the status window print this under the rule's name, so the two describe a
// rule identically.
func (a App) Summary() string {
	switch a.Kind {
	case AppFolder:
		return "every .exe in " + a.Value
	case AppStore:
		return "Store app " + a.Value + ", across updates"
	case AppTitle:
		return `any window whose title contains "` + a.Value + `"`
	default:
		if hasPathSep(a.Value) {
			return a.Value
		}
		return a.Value + ", wherever it is installed"
	}
}

// key identifies a rule for deduplication and lookup: kind plus a
// case-insensitive value, since paths, image names and package names are all
// case-insensitive on Windows and window titles are matched that way too.
func (a App) key() string {
	k := a.Kind
	if k == "" {
		k = AppExe
	}
	return strings.ToLower(k) + "\x00" + strings.ToLower(a.Value)
}

// BlockedApps returns the rules to enforce right now: the enabled entries,
// normalized and deduplicated, with anything unparseable left out (Validate
// reports those).
func (c Config) BlockedApps() []App { return c.normalizedApps(false) }

// InactiveApps returns the rules that are configured but currently switched off,
// either by their own flag or because a schedule window closed.
//
// ApplyApps needs these to prune, for the same reason the browser policies do:
// the launch block is a registry key per executable, so writing only the active
// set would leave an app blocked after its window closed.
func (c Config) InactiveApps() []App { return c.normalizedApps(true) }

func (c Config) normalizedApps(wantDisabled bool) []App {
	seen := make(map[string]bool, len(c.Apps))
	out := make([]App, 0, len(c.Apps))
	for _, a := range c.Apps {
		if a.Disabled != wantDisabled {
			continue
		}
		n, err := NormalizeApp(a.Kind, a.Value, a.Label)
		if err != nil || seen[n.key()] {
			continue
		}
		seen[n.key()] = true
		out = append(out, n)
	}
	return out
}

// AnyApps reports whether any application rule is configured at all, enabled or
// not. The service checks this before doing any sweep work, so an install that
// blocks only extensions and sites pays nothing for this feature.
func (c Config) AnyApps() bool { return len(c.Apps) > 0 }

func (c Config) findApp(kind, value string) (int, bool) {
	want, err := NormalizeApp(kind, value, "")
	if err != nil {
		return 0, false
	}
	for i, a := range c.Apps {
		if n, err := NormalizeApp(a.Kind, a.Value, ""); err == nil && n.key() == want.key() {
			return i, true
		}
	}
	return 0, false
}

// appListed reports whether a value names a configured app rule, resolving it
// against each entry's own kind. A block's app list carries values only, so this
// is how "is this in the catalog?" is answered without the caller knowing which
// kind the value belongs to.
func (c Config) appListed(value string) bool {
	for _, a := range c.Apps {
		want, err := NormalizeApp(a.Kind, value, "")
		if err != nil {
			continue
		}
		if n, err := NormalizeApp(a.Kind, a.Value, ""); err == nil && n.key() == want.key() {
			return true
		}
	}
	return false
}

// GovernedApp reports whether any block governs this app rule - that is, whether
// it is enforced on a schedule rather than around the clock. The status window
// labels those, otherwise an app reachable outside its window looks like a fault.
func (c Config) GovernedApp(a App) bool {
	for _, b := range c.Blocks {
		if b.GovernsApp(a) {
			return true
		}
	}
	return false
}

// AppCoveredBy returns the enabled folder rule that already blocks an
// executable, and whether one exists. Adding C:\Games\Steam\steam.exe when
// C:\Games\Steam is already blocked tightens nothing, and a list with redundant
// entries is harder to read and slower to sweep.
func (c Config) AppCoveredBy(kind, value string) (App, bool) {
	want, err := NormalizeApp(kind, value, "")
	if err != nil || want.Kind != AppExe || !hasPathSep(want.Value) {
		return App{}, false
	}
	for _, a := range c.Apps {
		if a.Disabled {
			continue
		}
		n, err := NormalizeApp(a.Kind, a.Value, a.Label)
		if err != nil || n.Kind != AppFolder {
			continue
		}
		if underFolder(n.Value, want.Value) {
			return n, true
		}
	}
	return App{}, false
}

// AddApp adds a rule in normalized form, or re-enables it if it is already
// listed but switched off. It reports the stored rule and whether the config
// changed.
func (c *Config) AddApp(kind, value, label string) (App, bool, error) {
	app, err := NormalizeApp(kind, value, label)
	if err != nil {
		return App{}, false, err
	}
	// Refused here rather than in NormalizeApp, so that a config already holding
	// a generic rule keeps loading and keeps its schedule. See genericImages.
	if app.Kind == AppExe && !hasPathSep(app.Value) && GenericImage(app.Value) {
		return App{}, false, fmt.Errorf("%s is a name many programs use, so blocking it by name alone would block them too - give the full path to the one you mean, or block its folder with -kind folder", app.Value)
	}
	if parent, ok := c.AppCoveredBy(app.Kind, app.Value); ok {
		return app, false, fmt.Errorf("%s is already covered by %s, which blocks everything in it",
			baseName(app.Value), parent.Value)
	}
	if i, ok := c.findApp(app.Kind, app.Value); ok {
		if !c.Apps[i].Disabled {
			return c.Apps[i], false, nil // already blocked
		}
		c.Apps[i].Disabled = false
		if app.Label != "" {
			c.Apps[i].Label = app.Label
		}
		return c.Apps[i], true, nil
	}
	if len(c.Apps)+1 > maxAppEntries {
		return App{}, false, fmt.Errorf("the app block list is full (%d entries)", maxAppEntries)
	}
	c.Apps = append(c.Apps, app)
	return app, true, nil
}

// SetAppEnabled switches one listed rule on or off, leaving it in the list. It
// reports the stored rule and false if no such rule is configured.
func (c *Config) SetAppEnabled(kind, value string, enabled bool) (App, bool) {
	i, ok := c.findApp(kind, value)
	if !ok {
		return App{}, false
	}
	c.Apps[i].Disabled = !enabled
	return c.Apps[i], true
}

// SetAppSource stamps provenance on one listed rule, leaving everything about
// what it enforces alone. It reports false if no such rule is configured.
//
// Whether a rule *should* be stamped is the caller's decision, not this one -
// see ApplyCategory, which stamps only what it added itself, so that a rule
// somebody blocked by hand is never claimed by a category that happens to name
// it too.
func (c *Config) SetAppSource(kind, value, source string) bool {
	i, ok := c.findApp(kind, value)
	if !ok {
		return false
	}
	c.Apps[i].Source = strings.TrimSpace(source)
	return true
}

// validateApps checks the configured list, and is called by Validate.
func (c Config) validateApps() error {
	seen := make(map[string]bool, len(c.Apps))
	for _, a := range c.Apps {
		n, err := NormalizeApp(a.Kind, a.Value, a.Label)
		if err != nil {
			return fmt.Errorf("blocked app: %w", err)
		}
		if seen[n.key()] {
			return fmt.Errorf("app %q is listed more than once", n.Value)
		}
		seen[n.key()] = true
	}
	if len(seen) > maxAppEntries {
		return fmt.Errorf("%d apps configured, more than the %d limit", len(seen), maxAppEntries)
	}
	return nil
}

// --- path handling -----------------------------------------------------------
//
// Windows paths are handled here rather than with path/filepath, because these
// values are Windows paths whatever platform is reading them: the config is
// written on Windows, and a test must not behave differently because it runs on
// Linux. Separators are normalized to backslash and comparison is
// case-insensitive, which is how the filesystem itself behaves.

// normalizeWinPath converts forward slashes to backslashes and trims surrounding
// whitespace, leaving case alone so the stored value still reads the way the user
// chose it.
func normalizeWinPath(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(s), "/", `\`))
}

func hasPathSep(s string) bool { return strings.Contains(s, `\`) }

// isAbsWinPath reports whether a path is rooted: a drive path (C:\...) or a UNC
// share (\\server\share). A relative path cannot be compared against a process
// image path, so rules refuse one.
func isAbsWinPath(s string) bool {
	if strings.HasPrefix(s, `\\`) {
		return true
	}
	return len(s) >= 3 && s[1] == ':' && s[2] == '\\' && isDriveLetter(s[0])
}

func isDriveLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isRootPath reports whether a path is a whole drive or the root of a UNC share.
func isRootPath(s string) bool {
	t := trimTrailingSep(s)
	if len(t) == 2 && t[1] == ':' && isDriveLetter(t[0]) {
		return true
	}
	if strings.HasPrefix(t, `\\`) {
		// \\server or \\server\share - both are too broad to be a folder rule.
		return strings.Count(strings.Trim(t, `\`), `\`) < 2
	}
	return false
}

// trimTrailingSep drops trailing backslashes, except the one that makes "C:\" a
// path at all.
func trimTrailingSep(s string) string {
	for len(s) > 0 && s[len(s)-1] == '\\' {
		if len(s) == 3 && s[1] == ':' {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

// baseName is the file-name part of a Windows path.
func baseName(s string) string {
	s = trimTrailingSep(s)
	if i := strings.LastIndexAny(s, `\/`); i >= 0 {
		return s[i+1:]
	}
	return s
}

// extension is the file extension of a name, including the dot.
func extension(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i:]
	}
	return ""
}

// samePath compares two Windows paths for equality, case-insensitively.
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(trimTrailingSep(normalizeWinPath(a)), trimTrailingSep(normalizeWinPath(b)))
}

// underFolder reports whether path is inside dir. The separator check is what
// stops "C:\Games\Doom" from being read as inside "C:\Games\Do".
func underFolder(dir, path string) bool {
	if dir == "" || path == "" {
		return false
	}
	d := trimTrailingSep(normalizeWinPath(dir))
	p := trimTrailingSep(normalizeWinPath(path))
	if !strings.HasSuffix(d, `\`) {
		d += `\`
	}
	return len(p) > len(d) && strings.EqualFold(p[:len(d)], d)
}
