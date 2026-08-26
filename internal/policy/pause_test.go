package policy

import (
	"strings"
	"testing"
	"time"
)

// These cover the gap between what a lock promises and what a pause used to do.
// A lock is documented as something the password cannot release early; pausing
// protection tore the service down and lifted everything it held, and nothing
// consulted the lock on the way. CheckPausable is what closes that.

var pauseNow = time.Date(2026, 8, 20, 14, 0, 0, 0, time.UTC)

func lockedBlock(id string, until time.Time) Block {
	return Block{ID: id, Label: id, LockedUntil: until.Format(time.RFC3339)}
}

func TestPauseAllowedWithNoBlocks(t *testing.T) {
	if err := CheckPausable(Config{}, pauseNow); err != nil {
		t.Errorf("a config with no blocks refused a pause: %v", err)
	}
}

func TestPauseAllowedWhenNoBlockIsLocked(t *testing.T) {
	cfg := Config{Blocks: []Block{
		{ID: "evenings", Windows: []Window{{Start: "22:00", End: "06:00"}}},
		{ID: "work", Windows: []Window{{Start: "09:00", End: "17:00"}}},
	}}
	if err := CheckPausable(cfg, pauseNow); err != nil {
		t.Errorf("an unlocked schedule refused a pause: %v", err)
	}
}

// The case that matters: a live lock has to refuse, or "locked until Friday"
// means "locked until somebody pauses".
func TestPauseRefusedWhileABlockIsLocked(t *testing.T) {
	until := pauseNow.Add(72 * time.Hour)
	cfg := Config{Blocks: []Block{lockedBlock("weekend", until)}}

	err := CheckPausable(cfg, pauseNow)
	if err == nil {
		t.Fatal("a pause was allowed while a block was locked; the lock means nothing")
	}
	// The message has to name the block and say when it frees up - "no" without
	// either is a dead end for whoever is reading it.
	if !strings.Contains(err.Error(), "weekend") {
		t.Errorf("the refusal does not name the block: %v", err)
	}
	if !strings.Contains(err.Error(), until.Local().Format(time.RFC1123)) {
		t.Errorf("the refusal does not say when the lock lifts: %v", err)
	}
}

func TestPauseAllowedOnceTheLockHasExpired(t *testing.T) {
	cfg := Config{Blocks: []Block{lockedBlock("weekend", pauseNow.Add(-time.Minute))}}
	if err := CheckPausable(cfg, pauseNow); err != nil {
		t.Errorf("an expired lock still refused a pause: %v", err)
	}
}

// An unreadable deadline counts as locked, matching Block.LockedAt: a corrupted
// timestamp must not become a way out. Failing open here would make editing one
// character of the trusted config the cheapest bypass in the product.
func TestPauseRefusedWhenTheDeadlineIsUnreadable(t *testing.T) {
	cfg := Config{Blocks: []Block{{ID: "weekend", LockedUntil: "next friday"}}}
	err := CheckPausable(cfg, pauseNow)
	if err == nil {
		t.Fatal("an unreadable lockedUntil allowed a pause; a corrupt deadline must fail closed")
	}
	if !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("the refusal does not say the deadline could not be read: %v", err)
	}
}

// One locked block among many still refuses, wherever it sits in the list - a
// pause turns everything off, so there is no partial version of the question.
func TestPauseRefusedByALockAnywhereInTheList(t *testing.T) {
	locked := lockedBlock("weekend", pauseNow.Add(24*time.Hour))
	unlocked := Block{ID: "work", Windows: []Window{{Start: "09:00", End: "17:00"}}}

	for name, blocks := range map[string][]Block{
		"locked first": {locked, unlocked},
		"locked last":  {unlocked, locked},
	} {
		if err := CheckPausable(Config{Blocks: blocks}, pauseNow); err == nil {
			t.Errorf("%s: a pause was allowed despite a locked block", name)
		}
	}
}

// Uninstalling stays available on purpose - it is the documented escape hatch,
// and it is the reason refusing a pause is defensible rather than a trap. This
// pins the asymmetry: the same config that refuses a pause still permits the
// teardown, which lifts everything and takes the blocks with it.
func TestALockedBlockDoesNotBlockTheEscapeHatch(t *testing.T) {
	cfg := Config{Blocks: []Block{lockedBlock("weekend", pauseNow.Add(24*time.Hour))}}
	if err := CheckPausable(cfg, pauseNow); err == nil {
		t.Fatal("expected the pause to be refused")
	}
	// An uninstall replaces the enforced config with nothing. CheckLockedBlocks is
	// what guards config changes, and it is deliberately not consulted on the
	// teardown path - if that ever changes, the product becomes unremovable, which
	// docs/pc-version.md calls out as the line between this and malware.
	if err := CheckLockedBlocks(cfg, Config{}, pauseNow); err == nil {
		t.Fatal("CheckLockedBlocks stopped refusing block removal; the pause guard " +
			"relies on it being the config-edit gate and nothing more")
	}
}
