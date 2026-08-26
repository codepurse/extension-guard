package main

import (
	"testing"

	"github.com/codepurse/extension-guard/internal/policy"
)

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

// A rule that came from a category is listed under it, and one added by hand is
// not. Grouping is the whole visible payoff of categories: a flat list of thirty
// entries is one nobody reads.
func TestAppCategoryReadsTheSource(t *testing.T) {
	cases := []struct {
		source string
		want   string
		ok     bool
	}{
		{"category:social", "social", true},
		{"", "", false},
		{"typed by hand", "", false},
		// A source naming a category this build no longer ships still groups
		// under that id rather than silently rejoining the loose list.
		{"category:retired", "retired", true},
	}
	for _, c := range cases {
		got, ok := appCategory(policy.App{Kind: policy.AppExe, Value: "Discord.exe", Source: c.source})
		if got != c.want || ok != c.ok {
			t.Errorf("appCategory(%q) = %q,%v, want %q,%v", c.source, got, ok, c.want, c.ok)
		}
	}
}
