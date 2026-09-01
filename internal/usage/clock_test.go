package usage

import (
	"testing"
	"time"
)

// fakeClock drives the monotonic source by hand. Every test here is about the
// difference between real time passing and the wall clock claiming it did, and
// that difference cannot be produced by waiting.
type fakeClock struct{ elapsed time.Duration }

// use installs the fake for one test and puts the real source back afterwards.
func (f *fakeClock) use(t *testing.T) {
	t.Helper()
	prev := mono
	mono = func() time.Duration { return f.elapsed }
	t.Cleanup(func() { mono = prev })
}

// advance moves real time forward.
func (f *fakeClock) advance(d time.Duration) { f.elapsed += d }

func mustDay(t *testing.T, at time.Time) string {
	t.Helper()
	return at.Format("2006-01-02")
}

// The ordinary case: real time and the clock move together, and the tracker
// simply believes the clock.
func TestNowBelievesAClockThatIsKeepingUp(t *testing.T) {
	var f fakeClock
	f.use(t)
	tr := &Tracker{}

	start := time.Date(2026, 9, 1, 22, 0, 0, 0, time.UTC)
	if got := tr.Now(start); !got.Equal(start) {
		t.Fatalf("the first reading was %v, want %v", got, start)
	}
	for i := 0; i < 300; i++ {
		f.advance(time.Second)
		wall := start.Add(time.Duration(i+1) * time.Second)
		if got := tr.Now(wall); !got.Equal(wall) {
			t.Fatalf("at %ds the tracker said %v, want %v", i+1, got, wall)
		}
	}
	if tr.Skew() != 0 {
		t.Errorf("skew is %v on a clock that never moved", tr.Skew())
	}
}

// The bypass this whole thing exists for: the clock is wound past the reset hour
// to reach a day with nothing charged against it. Before the anchor, that handed
// back a full fresh budget for the price of a trip to the date settings.
func TestNowRefusesAClockWoundForwardIntoTomorrow(t *testing.T) {
	var f fakeClock
	f.use(t)
	tr := &Tracker{}

	// Late evening, most of the budget gone.
	start := time.Date(2026, 9, 1, 23, 30, 0, 0, time.UTC)
	tr.Now(start)

	// A second of real time passes, and the clock claims an hour did - enough to
	// be past midnight and into a new day.
	f.advance(time.Second)
	jumped := start.Add(time.Hour)
	got := tr.Now(jumped)

	if mustDay(t, got) != mustDay(t, start) {
		t.Errorf("the tracker moved to %s, want to stay on %s", mustDay(t, got), mustDay(t, start))
	}
	if want := start.Add(time.Second); !got.Equal(want) {
		t.Errorf("the tracker said %v, want %v - it should track real time, not the clock", got, want)
	}
	if skew := tr.Skew(); skew < 59*time.Minute {
		t.Errorf("skew is %v, want about an hour", skew)
	}
}

// The clock going back was already refused by LastDay at the ledger level; the
// tracker has to refuse it too, or the day key would name an earlier day than the
// one being charged.
func TestNowRefusesAClockWoundBack(t *testing.T) {
	var f fakeClock
	f.use(t)
	tr := &Tracker{}

	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tr.Now(start)
	f.advance(time.Second)

	got := tr.Now(start.Add(-6 * time.Hour))
	if want := start.Add(time.Second); !got.Equal(want) {
		t.Errorf("the tracker said %v, want %v", got, want)
	}
	if tr.Skew() >= 0 {
		t.Errorf("skew is %v, want a negative offset for a clock moved back", tr.Skew())
	}
}

// A machine that legitimately steps its clock - NTP after a suspend, a virtual
// machine resuming - must not be treated as an attack, or the day boundary would
// freeze on a machine doing nothing wrong.
func TestNowAcceptsAnOrdinaryCorrection(t *testing.T) {
	var f fakeClock
	f.use(t)
	tr := &Tracker{}

	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tr.Now(start)
	f.advance(time.Minute)

	// A minute of real time, and the clock says a minute and a half: inside the
	// tolerance, so it is a correction and the tracker takes it.
	corrected := start.Add(time.Minute + 30*time.Second)
	if got := tr.Now(corrected); !got.Equal(corrected) {
		t.Errorf("the tracker said %v, want it to accept %v", got, corrected)
	}
	if tr.Skew() != 0 {
		t.Errorf("skew is %v after an ordinary correction, want 0", tr.Skew())
	}
}

// The boundary itself is a correction, not a jump. A tolerance that excluded its
// own value would make the behaviour depend on a microsecond.
func TestToleranceBoundaryIsStillACorrection(t *testing.T) {
	var f fakeClock
	f.use(t)
	tr := &Tracker{}

	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tr.Now(start)
	f.advance(time.Second)

	atEdge := start.Add(time.Second + ClockTolerance)
	if got := tr.Now(atEdge); !got.Equal(atEdge) {
		t.Errorf("a drift of exactly ClockTolerance was refused: got %v, want %v", got, atEdge)
	}

	f.advance(time.Second)
	past := atEdge.Add(time.Second + ClockTolerance + time.Millisecond)
	if got := tr.Now(past); got.Equal(past) {
		t.Error("a drift of one millisecond past ClockTolerance was accepted")
	}
}

// Putting the clock back has to be believed again. Otherwise a machine whose
// clock was wrong once stays wrong until the service restarts, and the honest
// fix - correcting the clock - would appear to do nothing.
func TestNowBelievesTheClockAgainOnceItComesBack(t *testing.T) {
	var f fakeClock
	f.use(t)
	tr := &Tracker{}

	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tr.Now(start)

	f.advance(time.Second)
	tr.Now(start.Add(5 * time.Hour))
	if tr.Skew() == 0 {
		t.Fatal("a five-hour jump was not noticed")
	}

	f.advance(time.Second)
	back := start.Add(2 * time.Second)
	if got := tr.Now(back); !got.Equal(back) {
		t.Errorf("the tracker said %v after the clock was corrected, want %v", got, back)
	}
	if tr.Skew() != 0 {
		t.Errorf("skew is %v after the clock was put back, want 0", tr.Skew())
	}
}

// Real time carries the day over on its own. The guard must not be so strict
// that a machine left running overnight never reaches tomorrow.
func TestARealDayStillRollsOver(t *testing.T) {
	var f fakeClock
	f.use(t)
	tr := &Tracker{}

	start := time.Date(2026, 9, 1, 23, 0, 0, 0, time.UTC)
	tr.Now(start)

	// Two hours of real time, a second at a time, with the clock keeping step.
	var got time.Time
	for i := 1; i <= 2*60*60; i++ {
		f.advance(time.Second)
		got = tr.Now(start.Add(time.Duration(i) * time.Second))
	}
	if mustDay(t, got) != "2026-09-02" {
		t.Errorf("after two real hours past 23:00 the day is %s, want 2026-09-02", mustDay(t, got))
	}
	if tr.Skew() != 0 {
		t.Errorf("skew is %v on a clock that kept step all night", tr.Skew())
	}
}

// Observe charges against whatever day it is handed, so the guard is only worth
// anything if the caller asks Now for that day. This is the end-to-end shape of
// what the service does, and it is what would break if somebody later "simplified"
// the sweep back to using time.Now directly.
func TestBudgetSurvivesTheClockBeingWoundForward(t *testing.T) {
	var f fakeClock
	f.use(t)
	tr := &Tracker{}

	start := time.Date(2026, 9, 1, 23, 0, 0, 0, time.UTC)
	blocks := []string{"games"}

	// Half an hour of real use, charged a second at a time.
	for i := 0; i <= 30*60; i++ {
		wall := start.Add(time.Duration(i) * time.Second)
		tr.Observe(wall, mustDay(t, tr.Now(wall)), blocks, nil)
		f.advance(time.Second)
	}
	spentBefore := tr.Spent(mustDay(t, tr.Now(start.Add(30*60*time.Second))))["games"]
	if spentBefore < 29*time.Minute {
		t.Fatalf("only %v was charged over half an hour of use", spentBefore)
	}

	// Now the clock is wound two hours forward, well past midnight.
	f.advance(time.Second)
	jumped := start.Add(30*time.Minute + 2*time.Hour)
	day := mustDay(t, tr.Now(jumped))

	if spentAfter := tr.Spent(day)["games"]; spentAfter < spentBefore {
		t.Errorf("after winding the clock forward the budget shows %v spent, was %v - the day was handed back", spentAfter, spentBefore)
	}
}
