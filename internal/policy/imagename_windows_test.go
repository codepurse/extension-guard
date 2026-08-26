//go:build windows

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The whole point of this file is one syscall chain: load a version resource,
// find which language it is written in, read OriginalFilename out of it. Every
// step of that is easy to get subtly wrong in a way that returns "" forever -
// and "" is a legitimate answer, so a broken reader would look exactly like a
// machine full of software with no version resources, and the rename bypass
// would be quietly open again.
//
// So this reads real binaries. Windows' own are the only files guaranteed to be
// on any machine the guard runs on, and they are also the awkward case: their
// strings live in a side-by-side MUI resource, so the raw read answers
// "NOTEPAD.EXE.MUI". Both halves are checked - that the read works at all, and
// that Process.OriginalImage reduces it to the name the protected list holds.
func TestReadingRealBinariesFindsTheirCompiledInNames(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	// Two, so one absent or unreadable image does not fail the test on a machine
	// that happens to be missing it.
	candidates := []string{
		filepath.Join(root, "explorer.exe"),
		filepath.Join(root, "System32", "notepad.exe"),
		filepath.Join(root, "System32", "cmd.exe"),
	}

	read := 0
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		raw := originalFileName(path)
		if raw == "" {
			t.Errorf("%s has no readable compiled-in name; the version reader is not working", path)
			continue
		}
		read++

		// The reduced form has to be the executable's own name, which is what a
		// rule and the protected list are both written in terms of.
		got := (Process{OriginalName: raw}).OriginalImage()
		want := filepath.Base(path)
		if !strings.EqualFold(got, want) {
			t.Errorf("%s reports %q, reduced to %q, want %q", path, raw, got, want)
		}
	}
	if read == 0 {
		t.Fatal("none of the candidate system binaries could be read at all")
	}
}

// A protected system image must be recognized by its compiled-in name as read
// off the real file, not just by a string a test made up. This is the guardrail
// closing the loop against the actual machine.
func TestARealSystemBinaryIsRecognizedAsProtected(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	path := filepath.Join(root, "explorer.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no explorer.exe to read: %v", err)
	}

	// Renamed, as somebody trying to make the guard shoot the desktop would do.
	disguised := Process{
		PID:          900,
		Name:         "harmless.exe",
		Path:         `C:\Users\kid\harmless.exe`,
		OriginalName: originalFileName(path),
	}
	if !anyProtected(disguised) {
		t.Errorf("a copy of explorer.exe named harmless.exe (compiled-in name %q) is not protected",
			disguised.OriginalName)
	}
}

// Reading the same image twice must not read the file twice: the sweep asks about
// every running process once a second, and an uncached read would be a permanent
// background disk load for an answer that does not change.
func TestTheVersionReadIsCached(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	path := filepath.Join(root, "explorer.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no explorer.exe to read: %v", err)
	}

	versionCache.Lock()
	versionCache.m = make(map[string]versionEntry)
	versionCache.Unlock()

	if first := originalFileName(path); first == "" {
		t.Fatalf("%s has no readable compiled-in name", path)
	}

	versionCache.Lock()
	n := len(versionCache.m)
	versionCache.Unlock()
	if n != 1 {
		t.Fatalf("one read left %d cache entries, want 1", n)
	}

	// Counting entries would not prove anything - a re-read overwrites the same
	// key and leaves the count at one. So the cached name is replaced with
	// something the file does not contain: getting it back can only mean the entry
	// was served without the resource being read again.
	const sentinel = "sentinel-not-in-any-real-binary.exe"
	versionCache.Lock()
	for k, e := range versionCache.m {
		e.name = sentinel
		versionCache.m[k] = e
	}
	versionCache.Unlock()

	if got := originalFileName(path); got != sentinel {
		t.Errorf("a second read of an unchanged image re-read the resource (got %q)", got)
	}
}

// A path that is not there, and one that is not an executable, both answer ""
// rather than failing. Every caller treats "" as "match on the file name alone",
// so this is what keeps a missing resource from breaking a working rule.
func TestUnreadableImagesAnswerEmpty(t *testing.T) {
	if got := originalFileName(`C:\definitely\not\here\nothing.exe`); got != "" {
		t.Errorf("a missing file answered %q", got)
	}
	if got := originalFileName(""); got != "" {
		t.Errorf("an empty path answered %q", got)
	}

	plain := filepath.Join(t.TempDir(), "notanexe.exe")
	if err := os.WriteFile(plain, []byte("this is not a PE file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := originalFileName(plain); got != "" {
		t.Errorf("a file with no version resource answered %q", got)
	}
}

// The cache must never outlive the file it describes. This is a regression test
// for a real bug: an earlier version trusted an entry for a minute before
// re-checking the file, to save a stat per process per sweep. That made a
// repeatable bypass - put a harmless executable at a path, let it be cached,
// replace it with the blocked program renamed, and for the next minute the guard
// believed the harmless name. Two different programs written to the same path in
// quick succession is exactly that attack, and it is what this checks.
func TestReplacingTheFileAtAPathIsNoticedImmediately(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	first, err := os.ReadFile(filepath.Join(root, "System32", "notepad.exe"))
	if err != nil {
		t.Skipf("no notepad.exe to copy: %v", err)
	}
	second, err := os.ReadFile(filepath.Join(root, "explorer.exe"))
	if err != nil {
		t.Skipf("no explorer.exe to copy: %v", err)
	}

	path := filepath.Join(t.TempDir(), "chess.exe")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	got := (Process{OriginalName: originalFileName(path)}).OriginalImage()
	if !strings.EqualFold(got, "notepad.exe") {
		t.Fatalf("a copy of notepad.exe named chess.exe reports %q, want notepad.exe", got)
	}

	// Same path, different program, immediately - no waiting for any interval.
	if err := os.WriteFile(path, second, 0o600); err != nil {
		t.Fatal(err)
	}
	got = (Process{OriginalName: originalFileName(path)}).OriginalImage()
	if strings.EqualFold(got, "notepad.exe") {
		t.Error("the cache served the previous file's name after the file was replaced")
	}
	if !strings.EqualFold(got, "explorer.exe") {
		t.Errorf("the replaced file reports %q, want explorer.exe", got)
	}
}

// A renamed copy of a system binary is the guardrail's real test case, and worth
// pinning because a copy behaves differently from the original in place: the
// side-by-side MUI resource does not travel with it, so the neutral resource in
// the binary answers instead. Either way the protected list has to recognize it.
func TestARenamedCopyOfASystemBinaryIsStillProtected(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	b, err := os.ReadFile(filepath.Join(root, "explorer.exe"))
	if err != nil {
		t.Skipf("no explorer.exe to copy: %v", err)
	}
	path := filepath.Join(t.TempDir(), "harmless.exe")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	p := Process{PID: 900, Name: "harmless.exe", Path: path, OriginalName: originalFileName(path)}
	if !anyProtected(p) {
		t.Errorf("a renamed copy of explorer.exe (compiled-in name %q) is not protected", p.OriginalName)
	}
	// And a rule for the name it is wearing must not be able to fire on it.
	rule := App{Kind: AppExe, Value: "harmless.exe"}
	if got := BlockedProcesses([]App{rule}, []Process{p}); len(got) != 0 {
		t.Error("the sweep would terminate a renamed copy of explorer.exe")
	}
}
