package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/codepurse/extension-guard/internal/activity"
	"github.com/codepurse/extension-guard/internal/friction"
	"github.com/codepurse/extension-guard/internal/scm"
)

// This file holds the typing challenge: the second half of the gate in front of
// every action that weakens protection.
//
// The password answers whether you are allowed to do this. It does not answer
// whether you still mean to, several minutes from now - and a password you chose
// yourself is one keystroke away at the exact moment you least want it to be.
// The challenge is a string of random characters, printed on screen, that has to
// be typed out. Nothing about it is secret; the whole cost is the typing.
//
// The two gates are independent. A machine with a password and no challenge
// behaves exactly as it did before this existed, which is what every installed
// copy reads as. A machine with a challenge and no password still has the
// challenge - `guard friction` is its own setting, not a password option.
//
// Where this sits relative to everything else in the program: it is not an
// enforcement mechanism and it is not a lock. Anybody prepared to spend the
// minutes gets through, deliberately, because the person holding the password is
// the person the tool belongs to and a gate they could never pass would just get
// the program uninstalled instead. What it buys is that weakening protection
// stops being something that can happen faster than the decision to do it.

// errChallengePasted and errChallengeAborted separate the two ways typing the
// challenge ends badly, because they deserve different messages: one is somebody
// giving up, which is the gate working, and the other is somebody trying to get
// around it, which belongs in the activity log.
var (
	errChallengePasted  = errors.New("that was pasted, not typed")
	errChallengeAborted = errors.New("cancelled")
)

// holdConsoleOnError is set by the -hold-console flag, which the status window
// passes when it has opened a console for the guard to ask the challenge in.
//
// That console belongs to this process and closes the moment it exits, so
// without this every message explaining why an attempt failed would be on screen
// for a few milliseconds. The window can only report an exit code; the reason is
// here, and the reason is what tells somebody they mistyped character 12 rather
// than that the feature is broken.
var holdConsoleOnError bool

// holdConsole keeps a console the window opened on screen until somebody has read
// it. A no-op everywhere else, including an ordinary terminal, where the output
// stays put on its own.
func holdConsole() {
	if !holdConsoleOnError {
		return
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprint(os.Stderr, "Press Enter to close this window. ")
	var one [1]byte
	for {
		n, err := os.Stdin.Read(one[:])
		if err != nil || n == 0 {
			return
		}
		if one[0] == 13 || one[0] == 10 {
			return
		}
	}
}

// requireChallenge presents the typing challenge and exits unless it is typed
// out correctly. It is a no-op on a machine where no challenge is configured,
// which is every machine until somebody runs `guard friction on`.
//
// what names the action being attempted, for the message and for the log.
func requireChallenge(what string) {
	n, on := scm.GetFrictionChars()
	if !on {
		return
	}
	// A challenge cannot be presented down a pipe, and the honest thing to do is
	// refuse rather than wave the action through. The installer's uninstall is the
	// caller this actually affects - it runs the guard with a hidden window - and
	// the message says where to go instead, because silently skipping the gate
	// there would make the whole setting bypassable by uninstalling from Add or
	// Remove Programs.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		activity.Record(activity.Event{Kind: activity.ChallengeRefused, Target: what, Detail: "no terminal to type it in"})
		fmt.Fprintf(os.Stderr, "error: %s needs the typing challenge, and there is no terminal to type it in\n", what)
		fmt.Fprintln(os.Stderr, "(run the same command from an elevated Administrator terminal)")
		holdConsole()
		os.Exit(1)
	}

	challenge, err := friction.Challenge(n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("%s is gated behind a typing challenge.\n", capitalize(what))
	fmt.Printf("Type these %d characters exactly. Spaces and line breaks are ignored,\n", n)
	fmt.Println("and it has to be typed - pasting is refused.")
	fmt.Println()
	for _, row := range friction.Grouped(challenge) {
		fmt.Printf("  %s\n", row)
	}
	fmt.Println()

	for {
		typed, err := readChallenge(challenge)
		switch {
		case errors.Is(err, errChallengeAborted):
			fmt.Fprintln(os.Stderr, "\ncancelled; nothing was changed")
			holdConsole()
			os.Exit(1)
		case errors.Is(err, errChallengePasted):
			// Recorded, unlike a plain typo. Somebody reaching for the clipboard
			// here is the clearest signal there is that the gate is doing its job
			// and being worked around, and it is the one attempt that leaves no
			// other trace at all.
			activity.Record(activity.Event{Kind: activity.ChallengeFailed, Target: what, Detail: "pasted"})
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
			fmt.Fprintln(os.Stderr, "(nothing was changed)")
			holdConsole()
			os.Exit(1)
		case err != nil:
			fmt.Fprintf(os.Stderr, "\nerror reading the challenge: %v\n", err)
			holdConsole()
			os.Exit(1)
		}
		if friction.Matches(challenge, typed) {
			fmt.Println("\nthat matches.")
			return
		}
		// Where it went wrong, rather than just that it did. Nothing is given away
		// - the answer is on the screen above - and finding out at character 256
		// that something broke at character 12, with no idea which, is what makes
		// somebody decide the feature is broken and go and turn it off.
		at := friction.FirstDifference(challenge, typed)
		got := len(friction.Normalize(typed))
		activity.Record(activity.Event{Kind: activity.ChallengeFailed, Target: what, Detail: "mistyped"})
		fmt.Println()
		if got < n && at >= got {
			fmt.Fprintf(os.Stderr, "that is %d characters of %d - it has to be all of them.\n", got, n)
		} else {
			fmt.Fprintf(os.Stderr, "that does not match, from character %d onwards.\n", at+1)
		}
		fmt.Fprintln(os.Stderr, "the same challenge is still standing; try again, or press Esc to give up.")
		fmt.Println()
	}
}

// readChallenge reads one attempt at the challenge, a keystroke at a time.
//
// It reads in raw mode rather than a line at a time for one reason: a terminal
// cannot be stopped from pasting. The clipboard belongs to the terminal and not
// to this program, so the only thing that can be checked is whether the
// characters arrived at a speed fingers can produce. A sustained run of gaps
// below friction.PasteGap did not come from a keyboard.
//
// The status window comes through here too. It opens a real console for the
// elevated guard when a challenge exists (see App.execGuard) rather than
// collecting the answer itself, so this loop is the only implementation there is
// and the timing test is the only paste defence in either place.
//
// want is used only for its length, to size the echo and say how far the attempt
// got. Nothing here compares against it; that is friction.Matches' job.
func readChallenge(want string) (string, error) {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	// Restored on every path out, including the paste and abort ones, because a
	// terminal left in raw mode is a shell that no longer echoes what is typed
	// into it - a much worse thing to leave behind than a failed command.
	defer func() { _ = term.Restore(fd, old) }()

	fmt.Print("  ")
	var typed []byte
	var paste friction.PasteWatch
	last := time.Now()
	buf := make([]byte, 1)
	for {
		read, err := os.Stdin.Read(buf)
		if err != nil {
			return string(typed), err
		}
		if read == 0 {
			continue
		}
		c := buf[0]
		gap := time.Since(last)
		last = time.Now()

		switch {
		case c == 3, c == 27: // Ctrl+C, Esc
			return string(typed), errChallengeAborted
		case c == 13, c == 10: // Enter
			return string(typed), nil
		case c == 8, c == 127: // Backspace
			if len(typed) > 0 {
				typed = typed[:len(typed)-1]
				fmt.Print("\b \b")
				// The echo groups in eights, so crossing a boundary backwards has
				// to take the separator with it or the groups drift out of step
				// with the challenge printed above.
				if len(typed) > 0 && len(typed)%8 == 0 {
					fmt.Print("\b \b")
				}
			}
			paste.Reset()
			continue
		case c < 32:
			// Every other control byte is ignored rather than typed. An arrow key
			// arrives as an escape sequence whose first byte is Esc, which is
			// handled above as giving up - crude, but a challenge is not a line
			// editor and pretending it is would mean writing one.
			continue
		}

		// Paste detection. The first character has no gap to measure, and one fast
		// pair is a fast typist or a key repeat; it takes a sustained run.
		if len(typed) > 0 && paste.Saw(gap) {
			return string(typed), errChallengePasted
		}

		typed = append(typed, c)
		_, _ = os.Stdout.Write([]byte{c})
		// Echoed in the same groups of eight the challenge is printed in, so the
		// attempt lines up under it and the typist can see where they are without
		// counting.
		if len(typed)%8 == 0 {
			fmt.Print(" ")
		}
		if len(typed) >= len(want) {
			// Long enough to be right. Not submitted automatically - the person
			// typing decides they are done, and auto-submitting would make a single
			// stray character silently truncate a correct attempt.
			continue
		}
	}
}

// frictionCmd shows or changes the typing challenge.
//
// The gate on this setting inverts the way `harden` does, and it has to. Turning
// the challenge on, or making it longer, only strengthens protection, so it costs
// admin and nothing more. Turning it off, or making it shorter, is the step that
// weakens - and it is gated by the challenge *itself*, at the length currently in
// force. Without that, the whole feature would be one `guard friction off` away
// from gone, which is exactly the impulse it exists to outlast.
func frictionCmd(action string, chars int, password string) {
	cur, on := scm.GetFrictionChars()

	switch strings.ToLower(strings.TrimSpace(action)) {
	case "":
		if !on {
			fmt.Println("typing challenge: off")
			fmt.Println()
			fmt.Println("nothing stands in front of a weakening action except the password.")
			fmt.Printf("turn it on with `guard friction on` (%d characters by default)\n", friction.DefaultChars)
			return
		}
		fmt.Printf("typing challenge: on, %d characters\n", cur)
		fmt.Println()
		fmt.Println("every action that weakens protection asks for the password and then for")
		fmt.Println("these characters, typed out. Pasting is refused.")
		fmt.Println("turn it off with `guard friction off` - which asks for the challenge first")
		return

	case "on":
		want := chars
		if want == 0 {
			want = friction.DefaultChars
		}
		if err := friction.ValidChars(want); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		if on && want == cur {
			fmt.Printf("the typing challenge is already on at %d characters\n", cur)
			return
		}
		// Shortening is weakening, so it goes through the gate at the length that
		// is in force now - not the shorter one being asked for.
		if on && want < cur {
			requirePassword(password, fmt.Sprintf("shortening the typing challenge from %d to %d characters", cur, want))
		}
		must(scm.SetFrictionChars(want))
		switch {
		case !on:
			activity.Record(activity.Event{Kind: activity.ChallengeEnabled, Detail: fmt.Sprintf("%d characters", want)})
			fmt.Printf("typing challenge on, %d characters\n", want)
			fmt.Println()
			fmt.Println("from now on, weakening protection means typing those out by hand.")
			fmt.Println("that includes turning this back off.")
		case want > cur:
			activity.Record(activity.Event{Kind: activity.ChallengeEnabled, Detail: fmt.Sprintf("%d characters", want)})
			fmt.Printf("typing challenge lengthened from %d to %d characters\n", cur, want)
		default:
			activity.Record(activity.Event{Kind: activity.ChallengeDisabled, Detail: fmt.Sprintf("%d characters", want)})
			fmt.Printf("typing challenge shortened from %d to %d characters\n", cur, want)
		}

	case "off":
		if !on {
			fmt.Println("the typing challenge is already off")
			return
		}
		requirePassword(password, "turning off the typing challenge")
		must(scm.ClearFrictionChars())
		activity.Record(activity.Event{Kind: activity.ChallengeDisabled})
		fmt.Println("typing challenge off")
		fmt.Println("(the password still gates everything it gated before)")

	default:
		fmt.Fprintf(os.Stderr, "error: unknown action %q - use `guard friction`, `guard friction on` or `guard friction off`\n", action)
		os.Exit(2)
	}
}

// capitalize upper-cases the first letter of an action description, so it can
// start a sentence. The descriptions are written lower-case because every other
// use of them sits mid-sentence.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
