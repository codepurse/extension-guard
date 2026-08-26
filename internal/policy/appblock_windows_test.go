//go:build windows

package policy

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// withTestIFEO points the launch-block code at a throwaway key under HKCU. The
// real IFEO hive is machine-wide and decides whether programs start, so a test
// that wrote to it could leave an application blocked on the developer's machine.
func withTestIFEO(t *testing.T) string {
	t.Helper()
	const base = `Software\ExtensionGuardTest\IFEO`
	oldHive, oldRoot := ifeoHive, ifeoRoot
	ifeoHive, ifeoRoot = registry.CURRENT_USER, base
	if key, _, err := registry.CreateKey(ifeoHive, ifeoRoot, registry.ALL_ACCESS); err == nil {
		key.Close()
	}
	t.Cleanup(func() {
		removeTree(registry.CURRENT_USER, base)
		_ = registry.DeleteKey(registry.CURRENT_USER, `Software\ExtensionGuardTest`)
		ifeoHive, ifeoRoot = oldHive, oldRoot
	})
	return base
}

// removeTree deletes a key and everything under it (the registry API only deletes
// leaves).
func removeTree(hive registry.Key, path string) {
	if key, err := registry.OpenKey(hive, path, registry.ALL_ACCESS); err == nil {
		if subs, err := key.ReadSubKeyNames(-1); err == nil {
			for _, s := range subs {
				removeTree(hive, path+`\`+s)
			}
		}
		key.Close()
	}
	_ = registry.DeleteKey(hive, path)
}

func imageKey(t *testing.T, name string) registry.Key {
	t.Helper()
	key, err := registry.OpenKey(ifeoHive, ifeoRoot+`\`+name, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	return key
}

// A bare-name rule blocks every copy of the executable, which is one unfiltered
// Debugger and no filter.
func TestLaunchBlockByName(t *testing.T) {
	withTestIFEO(t)
	cfg := Config{Apps: []App{{Kind: AppExe, Value: "some-mygame.exe"}}}

	if err := syncLaunchBlocks(cfg.BlockedApps()); err != nil {
		t.Fatalf("syncLaunchBlocks: %v", err)
	}
	key := imageKey(t, "some-mygame.exe")
	defer key.Close()
	dbg, _, err := key.GetStringValue(debuggerValue)
	if err != nil {
		t.Fatalf("Debugger not written: %v", err)
	}
	if !ourDebugger(dbg) || !strings.Contains(strings.ToLower(dbg), "guard.exe") {
		t.Errorf("Debugger = %q, want a guard command", dbg)
	}
	if _, _, err := key.GetIntegerValue(useFilterValue); err == nil {
		t.Error("UseFilter is set for a rule that should block every copy")
	}
	if !launchBlocked("some-mygame.exe") {
		t.Error("launchBlocked = false right after writing the block")
	}
}

// A path rule blocks that copy and not another, which needs UseFilter plus a
// filter subkey naming the path.
func TestLaunchBlockByPath(t *testing.T) {
	withTestIFEO(t)
	const path = `C:\Games\Some\some-mygame.exe`
	if err := syncLaunchBlocks([]App{{Kind: AppExe, Value: path}}); err != nil {
		t.Fatalf("syncLaunchBlocks: %v", err)
	}

	key := imageKey(t, "some-mygame.exe")
	filter, _, err := key.GetIntegerValue(useFilterValue)
	if err != nil || filter != 1 {
		t.Errorf("UseFilter = %v, %v; want 1", filter, err)
	}
	if _, _, err := key.GetStringValue(debuggerValue); err == nil {
		t.Error("an unfiltered Debugger is set, which would block every copy")
	}
	subs, err := key.ReadSubKeyNames(-1)
	key.Close()
	if err != nil || len(subs) != 1 {
		t.Fatalf("filter subkeys = %v, %v; want exactly one", subs, err)
	}

	if !launchBlocked(path) {
		t.Error("launchBlocked = false for the blocked path")
	}
	if launchBlocked(`D:\Elsewhere\some-mygame.exe`) {
		t.Error("launchBlocked = true for a copy the rule does not name")
	}
	if launchBlocked("some-mygame.exe") {
		t.Error("launchBlocked = true for the bare name, but only one path is filtered")
	}
}

// A bare-name rule is broader than a path rule for the same executable, so when
// both are configured the broad one has to win - filtering would let the other
// copies through.
func TestLaunchBlockNameBeatsPath(t *testing.T) {
	withTestIFEO(t)
	apps := []App{
		{Kind: AppExe, Value: `C:\Games\some-mygame.exe`},
		{Kind: AppExe, Value: "some-mygame.exe"},
	}
	if err := syncLaunchBlocks(apps); err != nil {
		t.Fatalf("syncLaunchBlocks: %v", err)
	}
	key := imageKey(t, "some-mygame.exe")
	defer key.Close()
	if _, _, err := key.GetStringValue(debuggerValue); err != nil {
		t.Error("no unfiltered Debugger, so copies outside the named path would run")
	}
	if _, _, err := key.GetIntegerValue(useFilterValue); err == nil {
		t.Error("UseFilter is still set, which makes the unfiltered Debugger ignored")
	}
	if !launchBlocked(`D:\Anywhere\some-mygame.exe`) {
		t.Error("a copy elsewhere is not blocked")
	}
}

// Enforcement has to be reconciled rather than appended to: a rule that is
// switched off, or deleted from the config outright, must lose its launch block.
func TestSyncLaunchBlocksPrunesWhatIsNoLongerWanted(t *testing.T) {
	base := withTestIFEO(t)
	if err := syncLaunchBlocks([]App{{Kind: AppExe, Value: "some-mygame.exe"}}); err != nil {
		t.Fatalf("syncLaunchBlocks: %v", err)
	}
	// The rule vanishes entirely - not merely disabled - which is what a
	// hand-edited config adopted with `guard commit` can do.
	if err := syncLaunchBlocks(nil); err != nil {
		t.Fatalf("syncLaunchBlocks (empty): %v", err)
	}
	if launchBlocked("some-mygame.exe") {
		t.Error("the launch block survived the rule being removed")
	}
	if _, err := registry.OpenKey(ifeoHive, base+`\some-mygame.exe`, registry.QUERY_VALUE); err == nil {
		t.Error("an empty key was left behind")
	}
}

// The other half of that contract: anything under IFEO the guard did not write is
// left alone. Another tool's debugger setting is not ours to discard.
func TestSyncLaunchBlocksLeavesForeignEntriesAlone(t *testing.T) {
	base := withTestIFEO(t)
	const foreignDebugger = `"C:\Tools\some-debugger.exe"`
	key, _, err := registry.CreateKey(ifeoHive, base+`\other-app.exe`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatalf("seed foreign key: %v", err)
	}
	if err := key.SetStringValue(debuggerValue, foreignDebugger); err != nil {
		t.Fatalf("seed foreign debugger: %v", err)
	}
	key.Close()

	if err := syncLaunchBlocks([]App{{Kind: AppExe, Value: "some-mygame.exe"}}); err != nil {
		t.Fatalf("syncLaunchBlocks: %v", err)
	}
	if err := syncLaunchBlocks(nil); err != nil {
		t.Fatalf("syncLaunchBlocks (empty): %v", err)
	}

	other := imageKey(t, "other-app.exe")
	defer other.Close()
	got, _, err := other.GetStringValue(debuggerValue)
	if err != nil || got != foreignDebugger {
		t.Errorf("foreign Debugger = %q, %v; want it untouched", got, err)
	}
}

// A rule on an executable something else already debugs is refused rather than
// silently overwritten - and the error says so, because the sweep still closes the
// app and the user needs to know why the launch block is absent.
func TestLaunchBlockRefusesToClobberForeignDebugger(t *testing.T) {
	base := withTestIFEO(t)
	key, _, err := registry.CreateKey(ifeoHive, base+`\some-mygame.exe`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatalf("seed foreign key: %v", err)
	}
	if err := key.SetStringValue(debuggerValue, `"C:\Tools\some-debugger.exe"`); err != nil {
		t.Fatalf("seed foreign debugger: %v", err)
	}
	key.Close()

	err = syncLaunchBlocks([]App{{Kind: AppExe, Value: "some-mygame.exe"}})
	if err == nil {
		t.Fatal("expected a foreign debugger to be reported rather than replaced")
	}
	if !strings.Contains(err.Error(), "some-mygame.exe") {
		t.Errorf("error should name the executable, got %q", err)
	}
}

// RemoveApps is the authorized teardown: every launch block the guard owns goes,
// so an uninstalled guard does not leave applications unable to start.
func TestRemoveAppsClearsLaunchBlocks(t *testing.T) {
	withTestIFEO(t)
	cfg := Config{Apps: []App{
		{Kind: AppExe, Value: "some-mygame.exe"},
		{Kind: AppExe, Value: `C:\Games\other-mygame.exe`},
	}}
	if err := syncLaunchBlocks(cfg.BlockedApps()); err != nil {
		t.Fatalf("syncLaunchBlocks: %v", err)
	}
	if err := RemoveApps(cfg); err != nil {
		t.Fatalf("RemoveApps: %v", err)
	}
	if launchBlocked("some-mygame.exe") || launchBlocked(`C:\Games\other-mygame.exe`) {
		t.Error("a launch block survived RemoveApps")
	}
}

// The sweep has to actually close a blocked program, and must not close the guard
// itself. The test blocks its own executable by path and starts a copy of it: the
// child has to die, and the process running the sweep has to survive - which is
// the whole reason SweepApps skips its own pid.
func TestSweepClosesBlockedProcessButSparesItself(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate the test binary: %v", err)
	}
	child := exec.Command(self, "-test.run=TestSleepHelper", "-test.timeout=60s")
	child.Env = append(os.Environ(), "EXTENSION_GUARD_SLEEP_HELPER=1")
	if err := child.Start(); err != nil {
		t.Fatalf("start the child: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	t.Cleanup(func() {
		if child.Process != nil {
			_ = child.Process.Kill()
		}
	})

	cfg := Config{Apps: []App{{Kind: AppExe, Value: self}}}
	// The child may not be in the process table the instant Start returns, so give
	// the sweep a few attempts rather than racing it.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if err := SweepApps(cfg); err != nil {
			t.Fatalf("SweepApps: %v", err)
		}
		select {
		case <-done:
			return // closed, and we are obviously still running
		case <-time.After(250 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the blocked process was still running after 15s of sweeping")
		}
	}
}

// TestSleepHelper is the child process for the sweep test: it does nothing but
// stay alive long enough to be closed. It is skipped in a normal run.
func TestSleepHelper(t *testing.T) {
	if os.Getenv("EXTENSION_GUARD_SLEEP_HELPER") == "" {
		t.Skip("helper process for TestSweepClosesBlockedProcessButSparesItself")
	}
	time.Sleep(45 * time.Second)
}

// A Store app's DisplayName is read from a key any standard user can write, and
// it ends up in the status window and in an elevated command line. Escaping is
// what makes that safe; this narrows the value as well, so one boundary mistake
// is not sufficient on its own.
func TestSanitizeStoreName(t *testing.T) {
	cases := map[string]string{
		"Minecraft Launcher":            "Minecraft Launcher",
		"  Roblox  ":                    "Roblox",
		`evil\" -extensions x select "`: "evil -extensions x select",
		"line\r\nbreak":                 "linebreak",
		"tab\there":                     "tabhere",
		"":                              "",
		"\x00\x01\x02":                  "",
		strings.Repeat("A", 200):        strings.Repeat("A", 96),
	}
	for in, want := range cases {
		if got := sanitizeStoreName(in); got != want {
			t.Errorf("sanitizeStoreName(%q) = %q, want %q", in, got, want)
		}
	}
}
