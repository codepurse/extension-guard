package main

import "testing"

// The blocked-launch message names the application, and Windows hands us its full
// command line - so the path has to be reduced to something a person recognizes.
func TestBaseNameOf(t *testing.T) {
	cases := map[string]string{
		`C:\Games\Steam\steam.exe`: "steam.exe",
		`C:/Games/steam.exe`:       "steam.exe",
		"steam.exe":                "steam.exe",
		`C:\Games\Steam\`:          "Steam",
	}
	for in, want := range cases {
		if got := baseNameOf(in); got != want {
			t.Errorf("baseNameOf(%q) = %q, want %q", in, got, want)
		}
	}
}
