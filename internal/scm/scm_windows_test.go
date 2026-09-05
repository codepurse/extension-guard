//go:build windows

package scm

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

// TestDisabledSentinelRoundTrip exercises the real registry read/write path
// against HKCU (writable without admin) rather than the production HKLM root.
func TestDisabledSentinelRoundTrip(t *testing.T) {
	root := registry.CURRENT_USER
	t.Cleanup(func() { registry.DeleteKey(root, stateKeyPath) })

	if isDisabledIn(root) {
		t.Fatal("expected sentinel unset initially")
	}
	if err := setDisabledIn(root, true); err != nil {
		t.Fatalf("set true: %v", err)
	}
	if !isDisabledIn(root) {
		t.Fatal("expected disabled after set true")
	}
	if err := setDisabledIn(root, false); err != nil {
		t.Fatalf("set false: %v", err)
	}
	if isDisabledIn(root) {
		t.Fatal("expected not disabled after set false")
	}
}

// TestAcquireSingleton verifies a second acquire of the same name fails while
// the first handle is held.
func TestAcquireSingleton(t *testing.T) {
	const name = `Local\ExtensionGuardWatchdogTest`
	if !AcquireSingleton(name) {
		t.Fatal("first acquire should succeed")
	}
	if AcquireSingleton(name) {
		t.Fatal("second acquire should fail while the first is held")
	}
}

// TestPasswordHashStorage exercises the real registry string read/write/delete
// path against HKCU (writable without admin) rather than the production HKLM.
func TestPasswordHashStorage(t *testing.T) {
	root := registry.CURRENT_USER
	t.Cleanup(func() { registry.DeleteKey(root, stateKeyPath) })

	if _, ok := getStringIn(root, passwordValue); ok {
		t.Fatal("expected no hash initially")
	}
	if err := setStringIn(root, passwordValue, "bcrypt$hash$value"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok := getStringIn(root, passwordValue)
	if !ok || got != "bcrypt$hash$value" {
		t.Fatalf("get = %q, %v", got, ok)
	}
	if err := deleteValueIn(root, passwordValue); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := getStringIn(root, passwordValue); ok {
		t.Fatal("expected no hash after delete")
	}
}

// TestTrustedConfigStorage exercises the real registry path used by the trusted
// config store, against HKCU (writable without admin) rather than production
// HKLM. The payload is a realistic multi-line JSON document rather than a token
// string: the value has to survive newlines and grow well past a hash.
func TestTrustedConfigStorage(t *testing.T) {
	root := registry.CURRENT_USER
	t.Cleanup(func() { registry.DeleteKey(root, stateKeyPath) })

	const cfg = `{
  "extensions": [
    {
      "name": "sieve",
      "chrome": {
        "extensionId": "abcdefghijklmnopabcdefghijklmnop",
        "updateUrl": "https://clients2.google.com/service/update2/crx"
      }
    }
  ]
}
`

	if _, ok := getStringIn(root, trustedValue); ok {
		t.Fatal("expected no trusted config initially")
	}
	if err := setStringIn(root, trustedValue, cfg); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok := getStringIn(root, trustedValue)
	if !ok {
		t.Fatal("trusted config missing after set")
	}
	if got != cfg {
		t.Errorf("round-trip altered the document:\ngot:  %q\nwant: %q", got, cfg)
	}
	if err := deleteValueIn(root, trustedValue); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := getStringIn(root, trustedValue); ok {
		t.Fatal("expected no trusted config after delete")
	}
}

// TestClearMissingValue covers the case that broke "Enable protection": the
// state key exists (something else wrote a value into it) but the value being
// cleared was never written. Clearing it has to succeed, because Resume clears
// the pause value on every enable and a machine that has never been paused does
// not have one - so an error here stopped the enable before it reached the
// service install.
func TestClearMissingValue(t *testing.T) {
	root := registry.CURRENT_USER
	t.Cleanup(func() { registry.DeleteKey(root, stateKeyPath) })

	// Create the key via a different value, the way the real key comes to exist.
	if err := setDisabledIn(root, false); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := deleteValueIn(root, pausedValue); err != nil {
		t.Fatalf("clearing a value that was never written should succeed, got: %v", err)
	}
	// And still succeed when the key itself is gone.
	if err := registry.DeleteKey(root, stateKeyPath); err != nil {
		t.Fatalf("delete key: %v", err)
	}
	if err := deleteValueIn(root, pausedValue); err != nil {
		t.Fatalf("clearing with no key at all should succeed, got: %v", err)
	}
}
