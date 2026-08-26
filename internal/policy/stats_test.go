package policy

import (
	"testing"
	"time"

	"github.com/codepurse/extension-guard/internal/usage"
)

func TestUsageStatsShape(t *testing.T) {
	now := at(20, 19, 0)
	cfg := Config{Apps: []App{
		{Kind: AppExe, Value: "steam.exe", Label: "Steam"},
		{Kind: AppTitle, Value: "Solitaire"},
	}}
	led := usage.Ledger{
		Apps: map[string]map[string]int{
			cfg.DayKey(now):                     {"exe:steam.exe": 3600, "title:solitaire": 600, "exe:gone.exe": 60},
			cfg.DayKey(now.AddDate(0, 0, -1)):   {"exe:steam.exe": 1800},
			cfg.DayKey(now.AddDate(0, 0, -100)): {"exe:steam.exe": 999},
		},
		Span: map[string]int{
			cfg.DayKey(now):                   4000,
			cfg.DayKey(now.AddDate(0, 0, -1)): 1800,
		},
	}
	ledgerLoad = func() (usage.Ledger, usage.State) { return led, usage.StateOK }
	defer func() { ledgerLoad = usage.Load }()

	rep := cfg.UsageStats(now, 7)
	if !rep.Measured || rep.Unreadable {
		t.Fatalf("measured=%v unreadable=%v", rep.Measured, rep.Unreadable)
	}
	if len(rep.Days) != 7 {
		t.Fatalf("days=%d", len(rep.Days))
	}
	if len(rep.Rows) != 3 {
		t.Fatalf("rows=%d: %+v", len(rep.Rows), rep.Rows)
	}
	// Sorted by total, descending.
	if rep.Rows[0].Label != "Steam" || rep.Rows[0].Total != 90*time.Minute || rep.Rows[0].Today != time.Hour {
		t.Errorf("row0 = %+v", rep.Rows[0])
	}
	if rep.Rows[0].Detail == "" {
		t.Error("a configured rule has no detail")
	}
	// A rule the config no longer holds is kept and marked.
	var gone *UsageRow
	for i := range rep.Rows {
		if rep.Rows[i].Key == "exe:gone.exe" {
			gone = &rep.Rows[i]
		}
	}
	if gone == nil || !gone.Gone || gone.Label != "exe:gone.exe" {
		t.Errorf("gone row = %+v", gone)
	}
	// Out-of-span days are excluded from the total.
	if rep.Rows[0].Total == 90*time.Minute+999*time.Second {
		t.Error("a day outside the span was counted")
	}
	if rep.TodaySpan != 4000*time.Second || rep.TotalSpan != 5800*time.Second {
		t.Errorf("span today=%v total=%v", rep.TodaySpan, rep.TotalSpan)
	}
	if len(rep.ByDay) != 7 || rep.ByDay[0] != 4000*time.Second {
		t.Errorf("byDay = %v", rep.ByDay)
	}
}

func TestUsageStatsNoRules(t *testing.T) {
	rep := Config{Extensions: []Extension{{Name: "x"}}}.UsageStats(at(20, 19, 0), 7)
	if rep.Measured {
		t.Error("a config with no app rules reports it is measuring")
	}
}

func TestRunningAppsIgnoresWindowsAndCountsEachRuleOnce(t *testing.T) {
	cfg := Config{Apps: []App{{Kind: AppExe, Value: "steam.exe"}}}
	procs := []Process{{PID: 1, Name: "steam.exe"}, {PID: 2, Name: "steam.exe"}}
	got := cfg.RunningApps(procs)
	if len(got) != 1 || got[0] != "exe:steam.exe" {
		t.Fatalf("RunningApps = %v", got)
	}
	// A rule switched off records nothing.
	cfg.Apps[0].Disabled = true
	if got := cfg.RunningApps(procs); len(got) != 0 {
		t.Errorf("a disabled rule was recorded: %v", got)
	}
}

func TestLedgerKeyIsReadable(t *testing.T) {
	if got := (App{Kind: AppFolder, Value: `C:\Games\Epic`}).LedgerKey(); got != `folder:c:\games\epic` {
		t.Errorf("LedgerKey = %q", got)
	}
	// An empty kind is exe, matching every other default in this package.
	if got := (App{Value: "steam.exe"}).LedgerKey(); got != "exe:steam.exe" {
		t.Errorf("LedgerKey = %q", got)
	}
}
