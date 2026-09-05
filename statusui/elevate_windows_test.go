//go:build windows

package main

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// parseCommandLine asks Windows itself how a command line splits into arguments,
// so the round-trip below is checked against the real parser rather than against
// a second implementation of the same rules.
func parseCommandLine(t *testing.T, cmd string) []string {
	t.Helper()
	p, err := windows.UTF16PtrFromString(cmd)
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	var argc int32
	argv, err := windows.CommandLineToArgv(p, &argc)
	if err != nil {
		t.Fatalf("CommandLineToArgv(%q): %v", cmd, err)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(argv))))
	out := make([]string, 0, argc)
	for i := int32(0); i < argc; i++ {
		out = append(out, windows.UTF16ToString((*argv)[i][:]))
	}
	return out
}

// The guard is launched elevated with these arguments, and several of them are
// free-form text - a typed window title, a label, a picked path, and a Store
// app's DisplayName, which any standard user can write in HKCU. A value that
// escapes its own quoting becomes *arguments* to a privileged process: the
// `select` case below redirects the whole invocation at a subcommand that
// rewrites the enforced config with no password.
//
// So the property under test is exact round-tripping: whatever goes in comes back
// as one argument, byte for byte.
func TestBuildArgsCannotInjectArguments(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"plain", []string{"-config", `C:\Program Files\Ward\extension-ids.json`, "apps"}},
		{"spaces in a label", []string{"-label", "Work hours", "add-block"}},
		{"trailing backslash", []string{"-kind", "folder", "block-app", `D:\Games\`}},
		{"drive root", []string{"block-app", `D:\`}},
		{"embedded quote", []string{"-label", `He said "hi"`, "block-app", "steam.exe"}},
		{"quote then backslash", []string{"-label", `a"\`, "block-app", "x.exe"}},
		{"injection via escaped quote", []string{
			"-config", "cfg.json", "-kind", "title", "-label",
			`a\" -extensions blocknsfw select "`,
			"block-app", `a\" -extensions blocknsfw select "`,
		}},
		{"injection via doubled quotes", []string{"-label", `x"" -password guess disable "`, "block-app", "y.exe"}},
		{"injection via many backslashes", []string{"-label", `x\\\" remove "`, "block-app", "y.exe"}},
		{"empty value", []string{"-label", "", "block-app", "y.exe"}},
		{"tab", []string{"-label", "a\tb", "block-app", "y.exe"}},
	}
	for _, c := range cases {
		// ShellExecuteEx passes lpFile separately, so the child's command line is the
		// executable followed by these parameters - hence the argv[0] stand-in.
		line := `"C:\Program Files\Ward\guard.exe" ` + buildArgs(c.args)
		got := parseCommandLine(t, line)
		if len(got) != len(c.args)+1 {
			t.Errorf("%s: parsed %d arguments, want %d\n  line: %s\n  got:  %q",
				c.name, len(got)-1, len(c.args), line, got)
			continue
		}
		for i, want := range c.args {
			if got[i+1] != want {
				t.Errorf("%s: argument %d = %q, want %q\n  line: %s", c.name, i, got[i+1], want, line)
			}
		}
	}
}

// The subcommand is the last argument the window appends, and the first
// positional is what the guard dispatches on. This is the property an injection
// would break, stated on its own so a regression names it directly.
func TestBuildArgsKeepsTheSubcommandFirstPositional(t *testing.T) {
	args := []string{"-config", "cfg.json", "-kind", "title", "-label", `evil\" select "`, "block-app", `evil\" select "`}
	got := parseCommandLine(t, `"guard.exe" `+buildArgs(args))

	// Everything after the executable up to the first token that is not a flag or
	// a flag value: the first positional must be block-app and nothing else.
	var positionals []string
	for i := 1; i < len(got); i++ {
		if got[i] == "block-app" || got[i] == "select" || got[i] == "remove" || got[i] == "disable" {
			positionals = append(positionals, got[i])
		}
	}
	if len(positionals) != 1 || positionals[0] != "block-app" {
		t.Errorf("subcommand-shaped tokens = %v, want exactly [block-app]\n  argv: %q", positionals, got)
	}
}
