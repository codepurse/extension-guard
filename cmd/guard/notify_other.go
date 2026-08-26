//go:build !windows

package main

import (
	"fmt"
	"os"
)

// notifyBlocked prints the refusal. The launch-block mechanism that invokes this
// (Image File Execution Options) is Windows-only, so off Windows this command is
// only ever run by hand - which makes stderr the right place for it.
func notifyBlocked(name string) {
	fmt.Fprintf(os.Stderr, "%s is blocked by Extension Guard\n", name)
}
