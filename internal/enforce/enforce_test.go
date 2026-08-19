package enforce

import (
	"errors"
	"strings"
	"testing"

	"github.com/codepurse/extension-guard/internal/policy"
)

// fake is a controllable Enforcer for exercising Set behaviour.
type fake struct {
	name     string
	applyErr error
	rmErr    error
	statuses []Status
	applied  int
	removed  int
}

func (f *fake) Name() string { return f.name }
func (f *fake) Apply(policy.Config) error {
	f.applied++
	return f.applyErr
}
func (f *fake) Remove(policy.Config) error {
	f.removed++
	return f.rmErr
}
func (f *fake) Verify(policy.Config) []Status { return f.statuses }

// TestApplyRunsEveryEnforcerDespiteFailure is the property the service depends
// on: one backend failing must not leave the others unenforced. Stopping at the
// first error would mean a browser policy we lack rights for silently disabling
// app blocking too.
func TestApplyRunsEveryEnforcerDespiteFailure(t *testing.T) {
	first := &fake{name: "first", applyErr: errors.New("denied")}
	second := &fake{name: "second"}

	err := Set{first, second}.Apply(policy.Config{})
	if err == nil {
		t.Fatal("expected the failure to be reported")
	}
	if !strings.Contains(err.Error(), "first apply") {
		t.Errorf("error should name the failing enforcer, got %q", err)
	}
	if second.applied != 1 {
		t.Errorf("second enforcer applied %d times, want 1 - a failure must not short-circuit", second.applied)
	}
}

// TestRemoveRunsEveryEnforcerDespiteFailure: same reasoning for teardown. A
// half-failed uninstall must report rather than leave the machine locked with
// nothing left to manage the lock.
func TestRemoveRunsEveryEnforcerDespiteFailure(t *testing.T) {
	first := &fake{name: "first", rmErr: errors.New("denied")}
	second := &fake{name: "second"}

	err := Set{first, second}.Remove(policy.Config{})
	if err == nil {
		t.Fatal("expected the failure to be reported")
	}
	if !strings.Contains(err.Error(), "first remove") {
		t.Errorf("error should name the failing enforcer, got %q", err)
	}
	if second.removed != 1 {
		t.Errorf("second enforcer removed %d times, want 1", second.removed)
	}
}

func TestApplySucceedsQuietly(t *testing.T) {
	a, b := &fake{name: "a"}, &fake{name: "b"}
	if err := (Set{a, b}).Apply(policy.Config{}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if a.applied != 1 || b.applied != 1 {
		t.Errorf("applied counts = %d, %d; want 1, 1", a.applied, b.applied)
	}
}

func TestVerifyCollectsInSetOrder(t *testing.T) {
	a := &fake{name: "a", statuses: []Status{{Enforcer: "a", Target: "one"}}}
	b := &fake{name: "b", statuses: []Status{{Enforcer: "b", Target: "two"}, {Enforcer: "b", Target: "three"}}}

	got := Set{a, b}.Verify(policy.Config{})
	want := []string{"one", "two", "three"}
	if len(got) != len(want) {
		t.Fatalf("got %d statuses, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Target != w {
			t.Errorf("status %d target = %q, want %q", i, got[i].Target, w)
		}
	}
}

func TestEnforcedCount(t *testing.T) {
	st := []Status{{Enforced: true}, {Enforced: false}, {Enforced: true}}
	if n := EnforcedCount(st); n != 2 {
		t.Errorf("EnforcedCount = %d, want 2", n)
	}
	if n := EnforcedCount(nil); n != 0 {
		t.Errorf("EnforcedCount(nil) = %d, want 0", n)
	}
}

// TestExtensionsAdapterShape checks the real adapter maps policy's
// browser-specific vocabulary onto the general one. It asserts shape rather than
// values: whether a browser is installed or locked depends on the machine the
// test runs on, but the row count and labelling do not.
func TestExtensionsAdapterShape(t *testing.T) {
	e := Extensions{}
	if e.Name() != "extensions" {
		t.Errorf("Name = %q, want extensions", e.Name())
	}

	got := e.Verify(policy.Config{})
	if len(got) == 0 {
		t.Fatal("Verify returned no statuses")
	}
	for _, s := range got {
		if s.Enforcer != "extensions" {
			t.Errorf("status %+v has Enforcer %q, want extensions", s, s.Enforcer)
		}
		if s.Target == "" {
			t.Errorf("status %+v has an empty Target", s)
		}
	}
}

// TestDefaultSetIncludesExtensions guards against a future backend being added
// in a way that drops the original one.
func TestDefaultSetIncludesExtensions(t *testing.T) {
	var found bool
	for _, e := range Default() {
		if e.Name() == "extensions" {
			found = true
		}
	}
	if !found {
		t.Error("the default set no longer enforces extensions")
	}
}
