//go:build windows

package policy

import (
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file reads the file name an executable's author compiled into it - the
// OriginalFilename field of its version resource - so that a rule naming
// opera.exe still matches after somebody renames opera.exe.
//
// It exists because renaming was the one bypass nothing here corrected. Every
// other way around the guard is undone by something: a deleted policy key is
// rewritten within milliseconds, an edited config loses to the trusted copy, a
// stopped service is restarted by the watchdog. A renamed file is not tampering
// with the guard at all - it needs no privilege beyond writing to a directory you
// already own, it is done once, and there is nothing to put back. The name in the
// resource is not on the file system, so renaming the file does not touch it.
//
// What this is worth, stated plainly: it turns a right-click-rename into a job
// that needs a resource editor. That is the same bar the watchdog sets - it
// defeats casual and impulsive, not determined - and it is the bar this whole
// program is built to. A stripped or rewritten resource wins, and the honest
// ceiling in docs/pc-version.md has not moved.

// versionCache remembers what was read for an image, because the sweep runs about
// once a second over a process list that barely changes, and reading a resource
// off disk for every process every second would be a background disk load in
// exchange for the same answer.
//
// The entry keeps the file's size and modification time so a file swapped for
// another at the same path - which is what an update or a repack does - is noticed
// and read again rather than being served the previous file's name.
//
// Every lookup confirms size and mtime, which costs a stat - about 65
// microseconds on an ordinary Windows 11 desktop, so around 20ms a second across
// three hundred processes. That is paid on purpose. An earlier version of this
// trusted an entry for a minute before re-checking, to save exactly that, and it
// was wrong in the one direction that matters: a file swapped at a path the guard
// had already seen kept the previous file's name for up to a minute, which is a
// repeatable way to run a blocked program. Put a harmless executable at a path,
// let it be cached, replace it with the renamed one, and go. A stat per process is
// cheaper than that hole.
//
// What the stat buys is that only the resource read is cached, never the identity
// of the file at a path.
type versionEntry struct {
	name     string
	size     int64
	modNanos int64
}

var versionCache = struct {
	sync.Mutex
	m map[string]versionEntry
}{m: make(map[string]versionEntry)}

// versionCacheMax bounds the cache. The natural size is the number of distinct
// executables running, a few hundred at most; this is far above that and exists
// so that a machine starting thousands of short-lived processes from distinct
// paths cannot grow the map without limit. Reaching it clears the map rather than
// evicting cleverly: the cost of a cold cache here is one read per running image,
// and an LRU would be more code than the problem deserves.
const versionCacheMax = 2048

// originalFileName returns the name compiled into the executable at path, or ""
// when there is none to read.
//
// Empty is an ordinary answer, not a failure. Plenty of legitimate software ships
// no version resource, a resource can carry no OriginalFilename, and a file can
// be unreadable or already gone by the time the sweep asks. Every caller treats
// "" as "match on the file name alone", which is what the guard did before this
// existed - so nothing here can turn a working rule into a broken one.
func originalFileName(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	key := strings.ToLower(path)

	fi, err := os.Stat(path)
	if err != nil {
		// Unreadable or already gone. There is no way to tell whether a cached entry
		// still describes what is at this path, so it is not used: an answer that
		// cannot be confirmed is exactly the answer a swap would exploit.
		return ""
	}
	size, mod := fi.Size(), fi.ModTime().UnixNano()

	versionCache.Lock()
	e, hit := versionCache.m[key]
	versionCache.Unlock()
	if hit && e.size == size && e.modNanos == mod {
		return e.name
	}

	e = versionEntry{
		name:     readOriginalFileName(path),
		size:     size,
		modNanos: mod,
	}
	store(key, e)
	return e.name
}

func store(key string, e versionEntry) {
	versionCache.Lock()
	defer versionCache.Unlock()
	if len(versionCache.m) >= versionCacheMax {
		versionCache.m = make(map[string]versionEntry)
	}
	versionCache.m[key] = e
}

// readOriginalFileName does the actual resource read: load the version block,
// find out which language it is written in, then ask for OriginalFilename in that
// language.
//
// The translation step is the part that is easy to get wrong. A version resource
// holds its strings under a language and code-page pair, and there is no fixed
// one to assume - a binary built in Germany files its strings under a different
// key than one built in the US. VarFileInfo\Translation is the list of pairs the
// file actually carries, so the first of those is what to ask for. Guessing the
// usual 040904b0 works on most binaries and silently reads nothing on the rest,
// which is the failure mode this whole file exists to avoid.
func readOriginalFileName(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return ""
	}

	lang, ok := firstTranslation(buf)
	if !ok {
		return ""
	}

	var ptr unsafe.Pointer
	var chars uint32
	sub := `\StringFileInfo\` + lang + `\OriginalFilename`
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), sub, unsafe.Pointer(&ptr), &chars); err != nil {
		return ""
	}
	if ptr == nil || chars == 0 {
		return ""
	}
	// chars counts UTF-16 code units including the terminator on every Windows
	// version that documents it, but a resource can be malformed, so the string is
	// read to its own NUL within the reported length rather than trusting the count.
	return strings.TrimSpace(utf16PrefixToString(ptr, chars))
}

// firstTranslation reads the file's first language/code-page pair and renders it
// as the eight hex digits a StringFileInfo sub-block is keyed by.
func firstTranslation(buf []byte) (string, bool) {
	var ptr unsafe.Pointer
	var n uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&ptr), &n); err != nil {
		return "", false
	}
	// Each pair is two 16-bit values, so anything shorter than four bytes is not
	// one pair.
	if ptr == nil || n < 4 {
		return "", false
	}
	pair := (*[2]uint16)(ptr)
	return hex4(pair[0]) + hex4(pair[1]), true
}

// hex4 renders a 16-bit value as exactly four lowercase hex digits, which is the
// form a StringFileInfo key takes.
func hex4(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{
		digits[(v>>12)&0xf],
		digits[(v>>8)&0xf],
		digits[(v>>4)&0xf],
		digits[v&0xf],
	})
}

// utf16PrefixToString reads at most chars UTF-16 code units from ptr, stopping at
// the first NUL. It is bounded by the length the resource reported so a resource
// with no terminator cannot walk off the end of the buffer.
func utf16PrefixToString(ptr unsafe.Pointer, chars uint32) string {
	if chars > 1024 {
		// An OriginalFilename is a file name. Anything claiming to be longer than
		// this is a malformed resource, and there is nothing to gain by reading it.
		chars = 1024
	}
	u := unsafe.Slice((*uint16)(ptr), chars)
	for i, c := range u {
		if c == 0 {
			return windows.UTF16ToString(u[:i])
		}
	}
	return windows.UTF16ToString(u)
}
