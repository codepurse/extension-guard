//go:build windows

package policy

import (
	"fmt"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/windows"

	"github.com/codepurse/extension-guard/internal/scm"
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
// The Firefox family cannot be fixed from here. Mozilla's policy engine reads
// SOFTWARE\Policies\Mozilla\<app> once during startup and has no reload path at
// all, so a change made while Firefox or Zen is running takes effect the next
// time it starts. GeckoRunning exists so the window and the CLI can say that
// plainly instead of reporting a block that is not yet blocking.

var (
	modUserenv          = windows.NewLazySystemDLL("userenv.dll")
	procRefreshPolicyEx = modUserenv.NewProc("RefreshPolicyEx")
)

// Behind vars so a test can exercise the staleness bookkeeping without touching
// the registry - the seam trust.go uses for the trusted store, for the reason.
var (
	setStaleGecko = scm.SetStaleGecko
	getStaleGecko = scm.GetStaleGecko
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
	// The Chromium browsers are about to be told to re-read. The Firefox family
	// cannot be told anything, so note which of them are running right now: those
	// instances are from here on serving rules they can no longer be given, and the
	// window has to be able to say so for as long as that stays true.
	recordStaleGecko()
	if err := refreshPolicy(); err != nil {
		browserPolicyDirty.Store(true)
		return err
	}
	return nil
}

// recordStaleGecko stores the Firefox-family instances running at this moment,
// as "kind:pid" pairs.
//
// The pid is what keeps this honest. Recording the browser alone would go on
// warning after the user had restarted it - the very thing the warning asks for -
// and a browser that has restarted is reading the current rules. A pid that is
// gone matches nothing, so the warning clears itself without anything having to
// remember to clear it.
//
// Best effort: it needs a privileged process, and is only ever called from one
// that has just written HKLM policy. Where it fails, the note on the action
// itself still stands.
func recordStaleGecko() {
	procs := runningGecko()
	parts := make([]string, 0, len(procs))
	for _, g := range procs {
		parts = append(parts, fmt.Sprintf("%s:%d", g.browser.Kind, g.pid))
	}
	_ = setStaleGecko(strings.Join(parts, ","))
}

// StaleGecko lists the Firefox-family browsers still running the instance that
// was open when the policy last changed - the ones showing rules that are no
// longer the rules. Empty is the normal state, including on a machine where none
// of them is open.
func StaleGecko() []GeckoBrowser {
	rec, ok := getStaleGecko()
	if !ok || rec == "" {
		return nil
	}
	recorded := make(map[string]bool)
	for _, f := range strings.Split(rec, ",") {
		if f != "" {
			recorded[f] = true
		}
	}
	var out []GeckoBrowser
	seen := make(map[Kind]bool)
	for _, g := range runningGecko() {
		if seen[g.browser.Kind] {
			continue
		}
		if recorded[fmt.Sprintf("%s:%d", g.browser.Kind, g.pid)] {
			seen[g.browser.Kind] = true
			out = append(out, g.browser)
		}
	}
	return out
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

// GeckoRunning lists the Firefox-family browsers with a process running right
// now, which is exactly the set a domain change will not be visible in until they
// are restarted. Best effort: if the process list cannot be read, this says none
// rather than warning about a browser that may not even be open.
//
// It answers for the browsers this platform writes policy for, not for the family
// - a running browser nothing was written for has nothing to pick up on restart,
// so naming it would be a caveat about a change that never applied to it.
func GeckoRunning() []GeckoBrowser {
	var out []GeckoBrowser
	seen := make(map[Kind]bool)
	for _, g := range runningGecko() {
		if seen[g.browser.Kind] {
			continue
		}
		seen[g.browser.Kind] = true
		out = append(out, g.browser)
	}
	return out
}

// geckoProc is one running Firefox-family process: the browser it belongs to, and
// the pid identifying this particular run of it.
type geckoProc struct {
	browser GeckoBrowser
	pid     uint32
}

// runningGecko lists every Firefox-family process running now - all of them
// rather than one per browser, because a browser is still "the instance that was
// open" only while one of the pids it was made of is alive.
func runningGecko() []geckoProc {
	// No needs: this asks only whether a process by a given name exists, which the
	// plain snapshot answers. Nothing here is a block rule, so nothing here wants
	// paths, titles, or the name compiled into the image.
	procs, err := snapshotProcesses(SnapshotNeeds{})
	if err != nil && len(procs) == 0 {
		return nil
	}
	var out []geckoProc
	for _, g := range geckoBrowsers() {
		if g.Image == "" {
			continue
		}
		for _, p := range procs {
			if strings.EqualFold(p.Name, g.Image) {
				out = append(out, geckoProc{browser: g, pid: p.PID})
			}
		}
	}
	return out
}
