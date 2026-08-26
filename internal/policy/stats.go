package policy

import (
	"sort"
	"strings"
	"time"

	"github.com/codepurse/extension-guard/internal/usage"
)

// This file turns the measurement that time limits already perform into a record
// somebody can read: how long each blocked application was running, today and over
// the past weeks.
//
// It costs almost nothing new, which is why it is here rather than in a design of
// its own. The sweep already samples the process list once a second and matches
// every rule against it, and the ledger already keeps sixty days of counters
// because - as the comment on keepDays has said since limits shipped - "how much
// did I actually use this week" is the obvious next question. What was missing was
// only that the answer was filed per *limited block* and then never read.
//
// Three ways this deliberately differs from the limit counters it sits beside:
//
//   - It measures every enabled application rule, not only the ones a limit
//     covers. Otherwise a machine that blocks Steam outright - the common case -
//     would have no record at all, which is the case where "how much is this
//     actually being used" is most worth knowing.
//   - Out-of-window time counts. A limit refuses to charge time outside its
//     window, because it is a budget for those hours; this is a record of use, and
//     an hour spent at an hour the block does not cover is still an hour spent.
//   - It keeps counting while protection is paused. That is the same choice the
//     activity log makes - it records "anything that happens during" a pause - and
//     it fails the right way: a record that went quiet during exactly the window
//     usage is highest would be worse than no record.
//
// What is deliberately *not* measured is everything else on the machine. Cold
// Turkey's statistics screen finds distractions you had not thought to name,
// because it watches every process; this watches the rules the config already
// names. That is a real capability difference and it is chosen, not overlooked: a
// full history of every program somebody ran is a different product from a guard
// whose record is readable by the person it is about, and PRIVACY.md is the promise
// being kept.

// ledgerLoad is how the record is read. A var for the reason spentOn is one: tests
// supply a ledger without a file on disk.
var ledgerLoad = usage.Load

// Sample is one observation of the process list, split by what each half is for.
//
// Blocks are the limited blocks being used right now and decide enforcement -
// they spend budgets, and a budget reaching zero starts a launch block. Apps are
// the rules running right now and decide nothing at all; they are the record. One
// sample produces both because they come from the same walk of the process list,
// and charging them from one interval is what keeps them consistent with each
// other.
type Sample struct {
	Blocks []string
	Apps   []string
}

// Any reports whether the sample saw anything at all, so a caller can skip the
// bookkeeping on an idle machine.
func (s Sample) Any() bool { return len(s.Blocks) > 0 || len(s.Apps) > 0 }

// LedgerKey is the stable name an application rule is recorded under. It is
// deliberately not App.key(), which separates its parts with a NUL byte for
// use as a map key inside this package - this one is written to a JSON file a
// person may read, and has to survive being looked at.
//
// Kind is a fixed word from a short list, so splitting on the first colon is
// unambiguous even though a path value contains one of its own.
func (a App) LedgerKey() string {
	kind := a.Kind
	if kind == "" {
		kind = AppExe
	}
	return strings.ToLower(kind) + ":" + strings.ToLower(a.Value)
}

// RunningApps returns the ledger keys of every enabled application rule matching
// something running right now.
//
// Unlike RunningLimited it consults no window and no limit: this is a record of
// what was running, and narrowing it to what a block happens to be enforcing would
// make the record answer a question nobody asked of it.
func (c Config) RunningApps(procs []Process) []string {
	apps := c.BlockedApps()
	if len(apps) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(apps))
	var out []string
	for _, p := range procs {
		for _, a := range apps {
			if !a.Matches(p) {
				continue
			}
			// Once per rule per observation, however many copies are running: two
			// windows of the same game are not two hours of it.
			if key := a.LedgerKey(); !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
		}
	}
	return out
}

// DayKeys names the n days ending with the day at contains, newest first. It goes
// through DayKey so a configured reset hour applies to the record exactly as it
// applies to a budget.
func (c Config) DayKeys(at time.Time, n int) []string {
	if n <= 0 {
		return nil
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, c.DayKey(at.AddDate(0, 0, -i)))
	}
	return out
}

// UsageRow is one application rule's share of the record.
//
// Gone marks a rule the config no longer holds. Those rows are kept rather than
// dropped: time spent on something that was later unblocked is still time spent,
// and silently removing it would make a week's total change when a rule was
// deleted.
type UsageRow struct {
	Key    string
	Label  string
	Detail string
	Today  time.Duration
	Total  time.Duration
	Gone   bool
}

// UsageReport is the whole record over a span of days, ready to print or render.
//
// Span and the sum of the rows answer different questions and both are reported.
// An hour with two rules running is two hours of rules and one hour of the
// afternoon; which one a reader wants depends on whether they are asking "what cost
// me the most" or "how much of the day went".
type UsageReport struct {
	Days      []string
	Rows      []UsageRow
	TodaySpan time.Duration
	TotalSpan time.Duration
	// ByDay is the span per day, newest first, alongside Days. It is what a
	// per-day bar is drawn from.
	ByDay []time.Duration
	// Measured is false when there is nothing to measure - no application rule is
	// configured - so a reader is told that rather than shown an empty list and left
	// to conclude the feature is broken.
	Measured bool
	// Unreadable means a ledger exists and could not be parsed. Unlike a limit,
	// which fails closed and treats every budget as spent, a damaged record here
	// just means the history is missing: there is nothing to fail closed *to*, and
	// refusing to show today's counters because last Tuesday's are corrupt would
	// help nobody.
	Unreadable bool
}

// UsageStats builds the report for the n days ending now.
func (c Config) UsageStats(at time.Time, n int) UsageReport {
	rep := UsageReport{Days: c.DayKeys(at, n), Measured: c.AnyApps()}
	led, state := ledgerLoad()
	rep.Unreadable = state == usage.StateUnreadable
	if rep.Unreadable {
		return rep
	}

	today := c.DayKey(at)
	todayByKey := led.AppSpent(today)
	totalByKey := led.AppTotals(rep.Days)
	rep.TodaySpan = led.SpanOn(today)
	rep.TotalSpan = led.SpanTotal(rep.Days)
	for _, day := range rep.Days {
		rep.ByDay = append(rep.ByDay, led.SpanOn(day))
	}

	// Configured rules first, so a row can carry the label and the summary the rest
	// of the guard shows for it.
	known := make(map[string]App, len(c.Apps))
	for _, a := range c.BlockedApps() {
		known[a.LedgerKey()] = a
	}
	for _, a := range c.InactiveApps() {
		if _, ok := known[a.LedgerKey()]; !ok {
			known[a.LedgerKey()] = a
		}
	}

	seen := map[string]bool{}
	for key, total := range totalByKey {
		seen[key] = true
		rep.Rows = append(rep.Rows, usageRow(key, known, todayByKey[key], total))
	}
	// A rule used only today, on a ledger whose day keys have not caught up, would
	// otherwise be missing from a report that shows today's column.
	for key, td := range todayByKey {
		if !seen[key] {
			rep.Rows = append(rep.Rows, usageRow(key, known, td, td))
		}
	}

	sort.Slice(rep.Rows, func(i, j int) bool {
		if rep.Rows[i].Total != rep.Rows[j].Total {
			return rep.Rows[i].Total > rep.Rows[j].Total
		}
		return rep.Rows[i].Label < rep.Rows[j].Label
	})
	return rep
}

func usageRow(key string, known map[string]App, today, total time.Duration) UsageRow {
	row := UsageRow{Key: key, Today: today, Total: total}
	if a, ok := known[key]; ok {
		row.Label, row.Detail = a.Display(), a.Summary()
		return row
	}
	// No rule holds this key any more. Show the key itself rather than inventing a
	// name for it, and say why the row has no detail.
	row.Label, row.Detail, row.Gone = key, "no longer on the block list", true
	return row
}
