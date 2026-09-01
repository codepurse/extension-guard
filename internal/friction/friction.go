// Package friction generates and checks the typing challenge that stands in
// front of every action which weakens protection.
//
// The password answers "are you allowed to do this". It does not answer "did you
// mean to do this, and do you still mean it a few minutes from now" - and for a
// tool somebody installs to bind their own future self, that second question is
// the one that matters. A password you set yourself is one keystroke away at the
// exact moment you least want it to be.
//
// So the gate is a string of random characters, shown on screen, that has to be
// typed out. There is nothing secret about it: it is printed in full, and the
// whole cost is the typing. Two hundred and fifty-six characters is several
// minutes of deliberate work, which is long enough that the impulse it exists to
// outlast has usually passed.
//
// What this is not: a lock. Anybody willing to spend the minutes gets through,
// by design - the person holding the password is the person the tool belongs to,
// and a gate they could never pass would just get the program uninstalled. The
// claim is friction, and the docs say so in those words.
package friction

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// DefaultChars is how long a challenge is when nobody says otherwise.
//
// 256 was chosen rather than tuned: at the two to three characters a second that
// careful copying of random text actually runs at, it is a few minutes of work.
// Short enough to finish when you genuinely need to, long enough that it cannot
// be done without deciding to.
const DefaultChars = 256

// The range a challenge length may be set to. The floor is not zero because a
// challenge short enough to type without noticing is worse than none at all - it
// trains the reflex it exists to interrupt. The ceiling only exists so a typo in
// a flag cannot produce something nobody could ever complete.
const (
	MinChars = 16
	MaxChars = 4096
)

// alphabet is what a challenge is drawn from: lowercase letters and digits, with
// every ambiguous glyph removed - no i or l or 1, no o or 0.
//
// This is a usability decision doing security work. A challenge is read off a
// screen and copied by hand, and a character the reader cannot tell apart from
// another one produces failures that have nothing to do with intent. The person
// typing has already decided to spend the minutes; making them spend the minutes
// twice over a letter they could not identify teaches them the gate is broken
// rather than that it is serious.
//
// Case is deliberately not mixed, for the same reason. Length is where the cost
// comes from, and length is free.
const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// Paste detection, for the terminal. A console cannot be stopped from pasting -
// the clipboard belongs to the terminal, not to this program - so the CLI
// watches the clock instead. Characters that arrive faster than fingers can move
// were not typed.
//
// PasteGap is deliberately well under a fast typist's floor: 200 words a minute
// on ordinary prose is about 60ms a character, and random text is far slower than
// prose. PasteRun exists so that one fast pair, or a key repeat, is not mistaken
// for a paste - it takes a sustained run of impossible gaps.
//
// This is the whole of the paste defence, including for the status window: the
// window answers a challenge by opening a console and letting the guard ask in
// there, so the timing test is what stands in both places. Blocking the clipboard
// outright would be stronger, and would mean the window collecting the answer
// itself - which needs somewhere admin-only to keep a pending challenge, so that
// the process verifying an answer is not the one that was told what to accept.
// That is not built. What is claimed here is that a pasted answer is refused, not
// that pasting is impossible.
const (
	PasteGap = 20 * time.Millisecond
	PasteRun = 8
)

// PasteWatch decides whether characters are being typed or were pasted, from
// nothing but their arrival times.
//
// It lives here rather than in the terminal loop that feeds it so that the one
// piece of judgement in the whole paste defence can be tested. The loop around it
// is unavoidably about console handles and raw mode; this is the part that can be
// wrong, and a threshold that is wrong either way is invisible until somebody
// either walks through the gate or cannot get through it at all.
type PasteWatch struct{ fast int }

// Saw records a character arriving gap after the previous one, and reports
// whether the input has stopped looking like typing.
//
// The caller does not report the first character of an attempt: there is no
// previous keystroke to measure it against, and the gap since the prompt appeared
// says nothing about anything.
func (w *PasteWatch) Saw(gap time.Duration) bool {
	if gap < PasteGap {
		w.fast++
	} else {
		// One human-speed gap ends the run rather than decrementing it. A paste
		// arrives as an unbroken burst, so anything with a real pause in it is
		// somebody typing - possibly somebody typing fast, which is not the thing
		// being caught.
		w.fast = 0
	}
	return w.fast >= PasteRun
}

// Reset clears the run. The caller uses it after a backspace, where the gaps
// either side of the correction say nothing about how the rest was entered.
func (w *PasteWatch) Reset() { w.fast = 0 }

// Challenge returns a fresh challenge of n characters.
//
// crypto/rand rather than math/rand, and not because a challenge is a secret -
// it is printed on screen. It is because a predictable one could be typed ahead
// of being asked for, which would turn the minutes this gate costs into zero
// while leaving every message in the program still claiming they were spent.
func Challenge(n int) (string, error) {
	if err := ValidChars(n); err != nil {
		return "", err
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("could not generate a challenge: %w", err)
	}
	// Rejection-free mapping would bias the last few characters of the alphabet.
	// The bias is tiny and this is not a secret, but a modulo here would be the
	// kind of thing somebody later reads as a mistake, so draw again instead.
	out := make([]byte, 0, n)
	const limit = 256 - (256 % len(alphabet))
	for len(out) < n {
		for _, v := range b {
			if int(v) >= limit {
				continue
			}
			out = append(out, alphabet[int(v)%len(alphabet)])
			if len(out) == n {
				break
			}
		}
		if len(out) < n {
			if _, err := rand.Read(b); err != nil {
				return "", fmt.Errorf("could not generate a challenge: %w", err)
			}
		}
	}
	return string(out), nil
}

// ValidChars reports whether n is a length a challenge may be set to.
func ValidChars(n int) error {
	if n < MinChars || n > MaxChars {
		return fmt.Errorf("a challenge must be between %d and %d characters, not %d", MinChars, MaxChars, n)
	}
	return nil
}

// Normalize strips every space and line break from typed input.
//
// A challenge is displayed in groups and rows so it can be read at all, and the
// person copying it should not have to work out whether the layout is part of the
// answer. Whitespace carries no information here, so it is discarded on both
// sides of the comparison rather than being something to get right.
func Normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Matches reports whether typed input satisfies the challenge.
//
// Not constant-time, and it should not be: the challenge is on screen. Comparing
// it in constant time would imply it were a secret, and the next person reading
// this file would go looking for where it is kept safe.
func Matches(challenge, typed string) bool {
	return Normalize(challenge) == Normalize(typed)
}

// FirstDifference returns the index of the first character of typed input that
// does not match the challenge, or -1 when it matches in full. Input that is
// correct but short returns the length typed, which is where it stopped.
//
// This is reported back to the person typing on purpose. Nothing is given away -
// they are looking at the answer - and discovering at character 256 that
// something went wrong at character 12, with no idea which, is the experience
// that makes somebody conclude the feature is broken and go turn it off.
func FirstDifference(challenge, typed string) int {
	want, got := Normalize(challenge), Normalize(typed)
	for i := 0; i < len(want) && i < len(got); i++ {
		if want[i] != got[i] {
			return i
		}
	}
	if len(got) == len(want) {
		return -1
	}
	return min(len(got), len(want))
}

// Display layout. Groups of 8 separated by spaces, 6 groups to a line: short
// enough to hold one group in your head between reading it and typing it, narrow
// enough to fit a terminal nobody widened.
const (
	groupSize    = 8
	groupsPerRow = 6
)

// Grouped renders a challenge for a human to copy, in fixed groups and rows.
func Grouped(s string) []string {
	var rows []string
	var row []string
	for i := 0; i < len(s); i += groupSize {
		end := min(i+groupSize, len(s))
		row = append(row, s[i:end])
		if len(row) == groupsPerRow {
			rows = append(rows, strings.Join(row, " "))
			row = nil
		}
	}
	if len(row) > 0 {
		rows = append(rows, strings.Join(row, " "))
	}
	return rows
}
