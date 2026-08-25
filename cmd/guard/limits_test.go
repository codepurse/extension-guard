package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codepurse/extension-guard/internal/policy"
)

// These tests are about what the two listings actually print. The rules behind
// them live in internal/policy and are tested there; what is checked here is that
// a person running the command can tell the three states apart, because "on but
// not blocking anything yet" is exactly the state that reads as a fault when it is
// described badly.

// limitedCLIConfig has one block with a budget and one without, so every column
// below has both cases in it.
func limitedCLIConfig() policy.Config {
	return policy.Config{
		ResetAt: "04:00",
		Apps: []policy.App{
			{Kind: policy.AppExe, Value: "steam.exe", Label: "Steam"},
			{Kind: policy.AppExe, Value: "notepad.exe"},
		},
		Blocks: []policy.Block{
			{ID: "games", Label: "Games", Apps: []string{"steam.exe"}, Limit: "45m"},
			{ID: "hard", Label: "Always blocked", Apps: []string{"notepad.exe"}},
		},
	}
}

// noon on Thursday 20 August 2026: inside a 09:00-17:00 window, so the fixtures
// below mean the same thing whenever the suite happens to run.
func noon() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.Local) }

// spentOf builds the counters a listing is rendered against.
func spentOf(pairs map[string]time.Duration) policy.Spent {
	return policy.Spent{ByBlock: pairs}
}

func TestBuildBlockNormalizesALimit(t *testing.T) {
	cfg := limitedCLIConfig()

	// A bare number is minutes, and it is stored in the form the config should read
	// in rather than as it was typed.
	b, err := buildBlock(cfg, "evenings", blockSpec{label: "Evenings", apps: "steam.exe", limit: "90"})
	if err != nil {
		t.Fatalf("buildBlock: %v", err)
	}
	if b.Limit != "1h30m" {
		t.Errorf("limit stored as %q, want 1h30m", b.Limit)
	}
	if !b.Narrows() {
		t.Error("a block with a limit does not report that it narrows enforcement, so it would be created without the password")
	}
	// A limit with no window is a complete rule: 90 minutes a day, at any hour.
	if len(b.Windows) != 0 {
		t.Errorf("windows = %+v, want none", b.Windows)
	}

	// And an unusable one is refused here, with the flag still in front of the user,
	// rather than several steps later inside Validate.
	if _, err := buildBlock(cfg, "x", blockSpec{label: "X", apps: "steam.exe", limit: "soon"}); err == nil {
		t.Error("an unreadable limit was accepted")
	}
	if _, err := buildBlock(cfg, "x", blockSpec{label: "X", apps: "steam.exe", limit: "30h"}); err == nil {
		t.Error("a limit longer than a day was accepted")
	}
}

func TestBlocksListingNamesTheThreeStates(t *testing.T) {
	cfg := limitedCLIConfig()
	cfg.Blocks = append(cfg.Blocks, policy.Block{
		ID: "work", Apps: []string{"notepad.exe"},
		Windows: []policy.Window{{Start: "09:00", End: "17:00"}},
	})

	out := capture(t, func() { blocksAt(cfg, noon(), spentOf(nil)) })
	for _, want := range []string{"in budget", "enforcing", "45m of 45m left"} {
		if !strings.Contains(out, want) {
			t.Errorf("the listing does not mention %q:\n%s", want, out)
		}
	}
	// The block with no budget must not claim one.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "hard ") && !strings.Contains(line, "-") {
			t.Errorf("the unlimited block shows a limit: %q", line)
		}
	}
}

func TestLimitsListingShowsAllowedAndUsed(t *testing.T) {
	out := capture(t, func() { limitsAt(limitedCLIConfig(), noon(), spentOf(nil)) })
	for _, want := range []string{"games", "45m", "available", "04:00"} {
		if !strings.Contains(out, want) {
			t.Errorf("the listing does not mention %q:\n%s", want, out)
		}
	}
	// A block without a limit has no business in this listing.
	if strings.Contains(out, "hard") {
		t.Errorf("a block with no limit was listed:\n%s", out)
	}
}

func TestLimitsListingSaysWhenThereAreNone(t *testing.T) {
	out := capture(t, func() { limitsAt(policy.Config{}, noon(), spentOf(nil)) })
	if !strings.Contains(out, "no daily time limits configured") {
		t.Errorf("output does not say there are none:\n%s", out)
	}
	// And it says how to make one, because an empty list with no way forward is a
	// dead end.
	if !strings.Contains(out, "add-block") {
		t.Errorf("output does not say how to add one:\n%s", out)
	}
}

// A block whose budget is gone has to read as blocked rather than as idle - the
// two look identical in a listing that only knows about windows.
func TestBlocksListingSaysUsedUp(t *testing.T) {
	out := capture(t, func() {
		blocksAt(limitedCLIConfig(), noon(), spentOf(map[string]time.Duration{"games": 45 * time.Minute}))
	})
	if !strings.Contains(out, "enforcing") {
		t.Errorf("a spent budget does not read as enforcing:\n%s", out)
	}
	if strings.Contains(out, "in budget") {
		t.Errorf("a spent budget still reads as in budget:\n%s", out)
	}
	if !strings.Contains(out, "0m of 45m left") {
		t.Errorf("the remaining time is wrong:\n%s", out)
	}
}

// capture collects what fn writes to stdout. The listings print rather than
// return, which is right for a CLI and means this is the only way to test them.
func capture(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stdout = prev
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return <-done
}
