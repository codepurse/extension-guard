package friction

import (
	"strings"
	"testing"
	"time"
)

// A challenge has to be the length that was asked for, drawn only from the
// alphabet, and different every time. The last of those is the one that matters:
// a predictable challenge could be typed before it was asked for, which would
// turn the minutes this gate costs into none while every message in the program
// still claimed they had been spent.
func TestChallengeIsTheRightLengthAndNotRepeated(t *testing.T) {
	const n = 256
	first, err := Challenge(n)
	if err != nil {
		t.Fatalf("generating a challenge failed: %v", err)
	}
	if len(first) != n {
		t.Errorf("got %d characters, want %d", len(first), n)
	}
	for i, r := range first {
		if !strings.ContainsRune(alphabet, r) {
			t.Fatalf("character %d is %q, which is not in the alphabet", i, r)
		}
	}
	second, err := Challenge(n)
	if err != nil {
		t.Fatalf("generating a second challenge failed: %v", err)
	}
	if first == second {
		t.Error("two challenges in a row came out identical")
	}
}

// Every length in range has to work, including the boundaries - an off-by-one in
// the rejection loop would show up as a short string rather than an error.
func TestChallengeHonoursEveryLengthInRange(t *testing.T) {
	for _, n := range []int{MinChars, MinChars + 1, 100, DefaultChars, MaxChars} {
		got, err := Challenge(n)
		if err != nil {
			t.Errorf("length %d failed: %v", n, err)
			continue
		}
		if len(got) != n {
			t.Errorf("length %d produced %d characters", n, len(got))
		}
	}
}

// The floor is not zero on purpose: a challenge short enough to type without
// noticing trains the reflex it exists to interrupt. The ceiling only stops a
// mistyped flag producing something nobody could complete.
func TestChallengeRefusesLengthsOutOfRange(t *testing.T) {
	for _, n := range []int{-1, 0, 1, MinChars - 1, MaxChars + 1} {
		if err := ValidChars(n); err == nil {
			t.Errorf("length %d was accepted", n)
		}
		if _, err := Challenge(n); err == nil {
			t.Errorf("a challenge of %d characters was generated", n)
		}
	}
}

// The alphabet is a usability decision doing security work, so it is held by a
// test. A challenge is read off a screen and copied by hand; a glyph the reader
// cannot tell from another one produces failures that have nothing to do with
// intent, and teaches them the gate is broken rather than that it is serious.
func TestAlphabetHasNoAmbiguousCharacters(t *testing.T) {
	for _, bad := range []rune{'i', 'l', '1', 'o', '0', 'I', 'L', 'O'} {
		if strings.ContainsRune(alphabet, bad) {
			t.Errorf("the alphabet contains %q, which is too easy to misread", bad)
		}
	}
	if strings.ToLower(alphabet) != alphabet {
		t.Error("the alphabet mixes case, which doubles the error rate for no extra cost")
	}
	seen := map[rune]bool{}
	for _, r := range alphabet {
		if seen[r] {
			t.Errorf("the alphabet lists %q twice, which skews the draw", r)
		}
		seen[r] = true
	}
	if len(alphabet) < 16 {
		t.Errorf("the alphabet has only %d characters, which is too few to be worth typing", len(alphabet))
	}
}

// Layout is not part of the answer. The challenge is displayed in groups and rows
// so it can be read at all, and somebody copying it should not have to work out
// whether the spaces count.
func TestWhitespaceIsNotPartOfTheAnswer(t *testing.T) {
	const want = "abcdefgh23456789"
	cases := []string{
		"abcdefgh23456789",
		"abcdefgh 23456789",
		"abcd efgh 2345 6789",
		"  abcdefgh\n23456789  ",
		"abcdefgh\r\n23456789",
		"abcdefgh\t23456789",
	}
	for _, typed := range cases {
		if !Matches(want, typed) {
			t.Errorf("%q was not accepted", typed)
		}
	}
	if Matches(want, "abcdefgh2345678") {
		t.Error("a short answer was accepted")
	}
	if Matches(want, "abcdefgh234567890") {
		t.Error("a long answer was accepted")
	}
	if Matches(want, "abcdefgh23456788") {
		t.Error("a wrong last character was accepted")
	}
}

// The whitespace rule has to hold on the challenge side too, since Grouped is
// what produced the layout in the first place.
func TestAGroupedChallengeIsItsOwnAnswer(t *testing.T) {
	ch, err := Challenge(DefaultChars)
	if err != nil {
		t.Fatalf("generating a challenge failed: %v", err)
	}
	rows := Grouped(ch)
	if !Matches(ch, strings.Join(rows, "\n")) {
		t.Error("typing the challenge back exactly as it was displayed did not match")
	}
	if got := len(Normalize(strings.Join(rows, " "))); got != DefaultChars {
		t.Errorf("the displayed rows hold %d characters, want %d", got, DefaultChars)
	}
	for i, row := range rows {
		for _, group := range strings.Fields(row) {
			if len(group) > groupSize {
				t.Errorf("row %d has a group of %d characters, want at most %d", i, len(group), groupSize)
			}
		}
		if n := len(strings.Fields(row)); n > groupsPerRow {
			t.Errorf("row %d has %d groups, want at most %d", i, n, groupsPerRow)
		}
	}
}

// Grouped has to hold a length that does not divide evenly by the group or row
// size, since the last group and the last row are the ones an off-by-one drops.
func TestGroupedKeepsAnAwkwardLength(t *testing.T) {
	for _, n := range []int{MinChars, 17, 49, 255, DefaultChars} {
		s := strings.Repeat("a", n)
		if got := len(Normalize(strings.Join(Grouped(s), " "))); got != n {
			t.Errorf("a %d-character challenge displayed as %d characters", n, got)
		}
	}
}

// Reporting where an attempt went wrong is what stops a typo at character 12
// being discovered at character 256 with no idea which one broke it. Nothing is
// given away: the answer is on the screen.
func TestFirstDifferenceSaysWhereItWentWrong(t *testing.T) {
	cases := []struct {
		name      string
		challenge string
		typed     string
		want      int
	}{
		{"identical", "abcdefgh", "abcdefgh", -1},
		{"identical but laid out", "abcdefgh", "abcd efgh", -1},
		{"wrong at the start", "abcdefgh", "zbcdefgh", 0},
		{"wrong in the middle", "abcdefgh", "abcxefgh", 3},
		{"wrong at the end", "abcdefgh", "abcdefgz", 7},
		{"correct but short", "abcdefgh", "abcd", 4},
		{"empty", "abcdefgh", "", 0},
		{"correct then extra", "abcdefgh", "abcdefghz", 8},
	}
	for _, tc := range cases {
		if got := FirstDifference(tc.challenge, tc.typed); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

// The paste thresholds are the whole of the terminal's defence, so they are held
// where they can be read. PasteGap has to sit well under a fast typist's floor -
// 200 words a minute on ordinary prose is about 60ms a character, and random text
// is far slower than prose - and PasteRun has to be more than a couple, so one
// fast pair or a key repeat is not mistaken for a paste.
func TestPasteThresholdsStayDefensible(t *testing.T) {
	if PasteGap <= 0 {
		t.Fatal("PasteGap is not positive, so nothing would ever be detected")
	}
	if PasteGap.Milliseconds() > 40 {
		t.Errorf("PasteGap is %v, which is inside the range a fast typist reaches", PasteGap)
	}
	if PasteRun < 3 {
		t.Errorf("PasteRun is %d, which a key repeat could trip on its own", PasteRun)
	}
	if PasteRun > DefaultChars/4 {
		t.Errorf("PasteRun is %d, which is too much of a %d-character challenge to be caught in", PasteRun, DefaultChars)
	}
}

// The paste detector is the whole of the terminal's defence, and it is the one
// piece of the challenge that can be quietly wrong in both directions: too eager
// and a fast typist is accused of cheating, too slack and the gate is one Ctrl+V
// from useless. Both failures are invisible without a test.
func TestPasteWatchTellsTypingFromPasting(t *testing.T) {
	typed := 80 * time.Millisecond // an ordinary pace on random text
	quick := 30 * time.Millisecond // a fast typist, still above the threshold
	burst := 1 * time.Millisecond  // a clipboard

	t.Run("an ordinary pace never trips", func(t *testing.T) {
		var w PasteWatch
		for i := 0; i < DefaultChars; i++ {
			if w.Saw(typed) {
				t.Fatalf("flagged as pasted at character %d", i)
			}
		}
	})

	t.Run("a fast typist never trips", func(t *testing.T) {
		var w PasteWatch
		for i := 0; i < DefaultChars; i++ {
			if w.Saw(quick) {
				t.Fatalf("flagged as pasted at character %d", i)
			}
		}
	})

	t.Run("a burst trips, and only after a run", func(t *testing.T) {
		var w PasteWatch
		for i := 1; i < PasteRun; i++ {
			if w.Saw(burst) {
				t.Fatalf("flagged after only %d fast characters, want %d", i, PasteRun)
			}
		}
		if !w.Saw(burst) {
			t.Fatalf("not flagged after %d fast characters", PasteRun)
		}
	})

	t.Run("one human gap ends the run", func(t *testing.T) {
		var w PasteWatch
		// Just short of tripping, then a real pause, then just short again. A
		// counter that decayed instead of resetting would fire here, and a typist
		// who happens to hit two quick keys per word would be refused.
		for i := 1; i < PasteRun; i++ {
			w.Saw(burst)
		}
		if w.Saw(typed) {
			t.Fatal("a human-speed gap was itself treated as a paste")
		}
		for i := 1; i < PasteRun; i++ {
			if w.Saw(burst) {
				t.Fatalf("the run was not reset by the pause: flagged again at %d", i)
			}
		}
	})

	t.Run("a correction clears the run", func(t *testing.T) {
		var w PasteWatch
		for i := 1; i < PasteRun; i++ {
			w.Saw(burst)
		}
		w.Reset()
		for i := 1; i < PasteRun; i++ {
			if w.Saw(burst) {
				t.Fatalf("Reset did not clear the run: flagged again at %d", i)
			}
		}
	})

	t.Run("the boundary itself is not fast", func(t *testing.T) {
		var w PasteWatch
		for i := 0; i < DefaultChars; i++ {
			if w.Saw(PasteGap) {
				t.Fatalf("a gap of exactly PasteGap was treated as a paste at %d", i)
			}
		}
	})
}
