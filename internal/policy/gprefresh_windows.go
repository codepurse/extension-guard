//go:build windows

package policy

import (
	"fmt"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// Writing a browser policy key is not the same as the browser reading it. This
// file closes that gap, which is why blocking or unblocking a site used to look
// like it needed the browser restarted first.
//
// Chromium (Chrome, Edge, Brave) does not watch HKLM\SOFTWARE\Policies for
// changes. It asks Windows to signal it when *Group Policy* is refreshed
// (RegisterGPNotification) and otherwise re-reads the registry on a fallback
// timer of its own, on the order of a quarter of an hour. The guard writes those
// keys directly - there is no domain and no GPO to edit on the machines this runs
// on - and a direct write fires no notification. So a block sat in the registry,
// correct and verified, while the running browser carried on with the policy it
// read at startup. From the outside that is indistinguishable from "it only works
// after a restart".
//
// RefreshPolicyEx is what gpupdate.exe calls. Asking for a machine refresh runs
// the policy engine, which signals every registered listener when it finishes, so
// Chromium re-reads the keys within a second or two. The block then applies to
// the next navigation - an already-open tab keeps showing what it loaded until it
// is reloaded, which is how Chromium's URL filter works and not something a
// refresh changes.
//
// Firefox cannot be fixed from here. Its policy engine reads
// SOFTWARE\Policies\Mozilla\Firefox once during startup and has no reload path at
// all, so a change made while Firefox is running takes effect the next time it
// starts. FirefoxRunning exists so the window and the CLI can say that plainly
// instead of reporting a block that is not yet blocking.

var (
	modUserenv          = windows.NewLazySystemDLL("userenv.dll")
	procRefreshPolicyEx = modUserenv.NewProc("RefreshPolicyEx")
)

// rpForce reapplies every setting rather than only the ones Windows believes
// changed. A refresh is only requested after the guard has actually written a
// key, so the extra work is bounded and worth the certainty.
const rpForce = 1

// browserPolicyDirty records that a browser policy key was really written, as
// opposed to found already correct. It exists because Apply runs on every
// reconcile cycle - startup, tamper, the backstop timer, every schedule boundary
// - and a machine-wide policy refresh every few seconds to confirm that nothing
// changed would be a waste of the machine. In steady state nothing sets this and
// no refresh happens.
var browserPolicyDirty atomic.Bool

// markBrowserPolicyChanged is called from the registry writers, next to the write
// itself, so a new policy key added later cannot forget to ask for the refresh.
func markBrowserPolicyChanged() { browserPolicyDirty.Store(true) }

// refreshBrowserPolicy makes running Chromium browsers re-read their policy keys
// if any were changed since the last refresh. A no-op otherwise.
//
// A failure leaves the change requested rather than swallowing it, so the next
// reconcile cycle tries again; and even if every attempt fails, the browser's own
// fallback reload still picks the change up eventually. That is why callers treat
// this as best effort: the policy is already written and verified at this point,
// and how quickly the browser notices must not decide whether applying it
// succeeded.
func refreshBrowserPolicy() error {
	if !browserPolicyDirty.Swap(false) {
		return nil
	}
	if err := refreshPolicy(); err != nil {
		browserPolicyDirty.Store(true)
		return err
	}
	return nil
}

// refreshPolicy is the syscall, behind a var so a test can exercise the
// coalescing above without asking Windows for a real machine-wide policy refresh.
var refreshPolicy = refreshMachinePolicy

func refreshMachinePolicy() error {
	if err := procRefreshPolicyEx.Find(); err != nil {
		return err // no userenv.dll: nothing to do but let the browser's own timer handle it
	}
	// bMachine = TRUE: every key the guard writes is under HKLM.
	if r, _, err := procRefreshPolicyEx.Call(1, rpForce); r == 0 {
		return fmt.Errorf("refresh group policy: %w", err)
	}
	return nil
}

// FirefoxRunning reports whether Firefox has a process running right now, which
// is exactly the case where a domain change will not be visible until it is
// restarted. Best effort: if the process list cannot be read, this says no rather
// than warning about a browser that may not even be open.
func FirefoxRunning() bool {
	procs, err := snapshotProcesses(false, false)
	if err != nil && len(procs) == 0 {
		return false
	}
	for _, p := range procs {
		if strings.EqualFold(p.Name, appPathExe[Firefox]) {
			return true
		}
	}
	return false
}
