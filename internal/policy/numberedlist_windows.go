//go:build windows

package policy

import (
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// Several browser policies are "lists" on Windows: a registry key whose values
// are named "1", "2", "3" and hold one entry each. ExtensionInstallForcelist,
// URLBlocklist and Firefox's WebsiteFilter\Block all use this shape.
//
// The numbering is load-bearing. Chromium's policy loader walks the names from
// "1" upward and stops at the first one missing, so a list with a hole in it is
// silently truncated - delete the value named "1" and a browser reads the whole
// list as empty while the registry still looks populated. Anything that removes
// an entry therefore has to renumber the rest, which is why removal and addition
// are one operation here rather than two.

// syncNumberedList reconciles the numbered list under path so that afterwards:
//
//   - every entry in want is present,
//   - every existing entry that drop reports is gone,
//   - every other existing entry is kept, because the machine's owner or an
//     administrator may have set up policies of their own and the guard has no
//     business discarding them, and
//   - the values are renumbered contiguously from "1".
//
// It does not create the key when there is nothing to add and nothing to remove,
// so a browser the config says nothing about is left completely alone.
func syncNumberedList(path string, want []string, drop func(string) bool) error {
	existing, names, err := readNumberedList(path)
	if err != nil {
		return err
	}
	if len(existing) == 0 && len(want) == 0 {
		return nil // nothing here and nothing wanted: do not create the key
	}

	wanted := make(map[string]bool, len(want))
	for _, w := range want {
		wanted[w] = true
	}

	// Keep foreign entries and anything still wanted; drop the rest.
	final := make([]string, 0, len(existing)+len(want))
	seen := make(map[string]bool, len(existing)+len(want))
	for _, v := range existing {
		if seen[v] {
			continue // a duplicate already in the registry; collapse it
		}
		if !wanted[v] && drop != nil && drop(v) {
			continue
		}
		seen[v] = true
		final = append(final, v)
	}
	for _, w := range want {
		if !seen[w] {
			seen[w] = true
			final = append(final, w)
		}
	}

	if sameOrder(existing, final) && len(names) == len(final) && contiguous(names) {
		return nil // already correct; avoid pointless registry churn
	}
	return writeNumberedList(path, final, names)
}

// readNumberedList returns the entries under path in index order, along with the
// value names actually present. A missing key is not an error - it reads as an
// empty list.
func readNumberedList(path string) ([]string, []string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return nil, nil, nil
	}
	defer key.Close()
	names, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, nil, err
	}
	// Read in numeric order so the kept entries stay in the order a person set
	// them up in, which makes the key readable in regedit.
	type slot struct {
		idx int
		val string
	}
	slots := make([]slot, 0, len(names))
	for _, n := range names {
		i, err := strconv.Atoi(n)
		if err != nil {
			continue // not part of the numbered list
		}
		v, _, err := key.GetStringValue(n)
		if err != nil || v == "" {
			continue
		}
		slots = append(slots, slot{i, v})
	}
	for i := 1; i < len(slots); i++ {
		for j := i; j > 0 && slots[j-1].idx > slots[j].idx; j-- {
			slots[j-1], slots[j] = slots[j], slots[j-1]
		}
	}
	out := make([]string, 0, len(slots))
	for _, s := range slots {
		out = append(out, s.val)
	}
	return out, names, nil
}

// writeNumberedList writes entries as "1".."n" under path and clears the value
// names that are no longer needed. Writing before deleting means a browser
// reading mid-update sees a complete list rather than a half-empty one.
func writeNumberedList(path string, entries []string, oldNames []string) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()

	for i, v := range entries {
		if err := key.SetStringValue(strconv.Itoa(i+1), v); err != nil {
			return err
		}
	}
	for _, n := range oldNames {
		i, err := strconv.Atoi(n)
		if err != nil {
			continue // leave values that are not part of the numbered list
		}
		if i > len(entries) {
			if err := key.DeleteValue(n); err != nil {
				return err
			}
		}
	}
	return nil
}

func sameOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// contiguous reports whether names are exactly "1".."n" with no gaps and nothing
// else mixed in.
func contiguous(names []string) bool {
	seen := make(map[int]bool, len(names))
	for _, n := range names {
		i, err := strconv.Atoi(n)
		if err != nil {
			return false
		}
		seen[i] = true
	}
	for i := 1; i <= len(names); i++ {
		if !seen[i] {
			return false
		}
	}
	return true
}
