package endpoint

import "testing"

func TestUnconfiguredYieldsNoURLs(t *testing.T) {
	old := Base
	Base = ""
	defer func() { Base = old }()

	if Configured() {
		t.Error("Configured() = true with an empty Base")
	}
	if u := Latest(); u != "" {
		t.Errorf("Latest() = %q, want empty so callers fall back", u)
	}
	if u := Announcement(); u != "" {
		t.Errorf("Announcement() = %q, want empty so callers fall back", u)
	}
}

func TestURLsJoinCleanly(t *testing.T) {
	cases := []struct{ base, latest, announce string }{
		{"https://updates.example.com", "https://updates.example.com/latest.json", "https://updates.example.com/announcement.json"},
		{"https://updates.example.com/", "https://updates.example.com/latest.json", "https://updates.example.com/announcement.json"},
		{"  https://updates.example.com/v1/  ", "https://updates.example.com/v1/latest.json", "https://updates.example.com/v1/announcement.json"},
	}
	old := Base
	defer func() { Base = old }()
	for _, c := range cases {
		Base = c.base
		if got := Latest(); got != c.latest {
			t.Errorf("Base=%q Latest() = %q, want %q", c.base, got, c.latest)
		}
		if got := Announcement(); got != c.announce {
			t.Errorf("Base=%q Announcement() = %q, want %q", c.base, got, c.announce)
		}
	}
}
