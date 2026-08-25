//go:build windows

package policy

import (
	"errors"
	"testing"
)

// stubRefresh replaces the syscall for the duration of a test and reports how
// many times a refresh was actually asked for. A real call would refresh group
// policy machine-wide, which no test has any business doing.
func stubRefresh(t *testing.T, err error) *int {
	t.Helper()
	calls := 0
	prev := refreshPolicy
	refreshPolicy = func() error {
		calls++
		return err
	}
	browserPolicyDirty.Store(false)
	t.Cleanup(func() {
		refreshPolicy = prev
		browserPolicyDirty.Store(false)
	})
	return &calls
}

// The reconcile cycle calls Apply on startup, on every tamper notification and on
// a backstop timer, so the common case by far is "nothing changed". Refreshing
// group policy each of those times would be a machine-wide operation to confirm
// that nothing needed doing.
func TestRefreshBrowserPolicySkippedWhenNothingChanged(t *testing.T) {
	calls := stubRefresh(t, nil)

	for i := 0; i < 3; i++ {
		if err := refreshBrowserPolicy(); err != nil {
			t.Fatalf("refreshBrowserPolicy: %v", err)
		}
	}
	if *calls != 0 {
		t.Fatalf("refreshed %d times with no policy change; want 0", *calls)
	}
}

// One apply can write several keys - a URL filter per browser, plus the forcelist.
// They must add up to a single refresh, and the next apply must not inherit it.
func TestRefreshBrowserPolicyCoalescesAndClears(t *testing.T) {
	calls := stubRefresh(t, nil)

	markBrowserPolicyChanged()
	markBrowserPolicyChanged()
	markBrowserPolicyChanged()
	if err := refreshBrowserPolicy(); err != nil {
		t.Fatalf("refreshBrowserPolicy: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("refreshed %d times for one batch of changes; want 1", *calls)
	}

	if err := refreshBrowserPolicy(); err != nil {
		t.Fatalf("second refreshBrowserPolicy: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("refreshed %d times; the flag was not cleared", *calls)
	}
}

// A refresh that fails leaves the change outstanding, so the next reconcile cycle
// retries it. Dropping it would leave the browser on a stale policy until its own
// fallback reload came round - the behaviour this whole file exists to avoid.
func TestRefreshBrowserPolicyRetriesAfterFailure(t *testing.T) {
	wantErr := errors.New("boom")
	calls := stubRefresh(t, wantErr)

	markBrowserPolicyChanged()
	if err := refreshBrowserPolicy(); !errors.Is(err, wantErr) {
		t.Fatalf("refreshBrowserPolicy = %v, want %v", err, wantErr)
	}
	if err := refreshBrowserPolicy(); !errors.Is(err, wantErr) {
		t.Fatalf("retry = %v, want the change still outstanding", err)
	}
	if *calls != 2 {
		t.Fatalf("refreshed %d times; want 2 (the failure retried)", *calls)
	}
}
