package policy

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"reddit.com", "reddit.com"},
		{"  Reddit.COM  ", "reddit.com"},
		{"reddit.com.", "reddit.com"},
		{"https://reddit.com", "reddit.com"},
		{"http://reddit.com/r/golang", "reddit.com"},
		{"https://www.reddit.com/r/x?sort=new#top", "reddit.com"},
		{"reddit.com:443", "reddit.com"},
		{"//reddit.com", "reddit.com"},
		{"user:pw@reddit.com", "reddit.com"},
		// A subdomain that is not "www" is meaningful and must survive.
		{"old.reddit.com", "old.reddit.com"},
		{"news.ycombinator.com", "news.ycombinator.com"},
		// Punycode passes through; it is already ASCII.
		{"xn--80ak6aa92e.com", "xn--80ak6aa92e.com"},
		{"a-b.example.co.uk", "a-b.example.co.uk"},
	}
	for _, c := range cases {
		got, err := NormalizeDomain(c.in)
		if err != nil {
			t.Errorf("NormalizeDomain(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestNormalizeDomainStripsWWW is called out separately because it is a judgement
// call, not a parse: someone typing www.reddit.com means Reddit, and keeping the
// prefix would leave old.reddit.com reachable.
func TestNormalizeDomainStripsWWW(t *testing.T) {
	got, err := NormalizeDomain("www.reddit.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "reddit.com" {
		t.Errorf("got %q, want reddit.com so that every subdomain is covered", got)
	}
}

func TestNormalizeDomainRejects(t *testing.T) {
	cases := []struct{ in, wantErr string }{
		{"", "empty"},
		{"   ", "empty"},
		{"https://", "no hostname"},
		// A lone "*" is a legal Chromium pattern meaning "block every URL". Reaching
		// it by typo would take the entire web out.
		{"*", "wildcards"},
		{"*.reddit.com", "wildcards"},
		{"redd?t.com", "wildcards"},
		{"reddit.com, twitter.com", "more than one domain"},
		{"reddit.com twitter.com", "more than one domain"},
		{"localhost", "not a domain"},
		{"reddit..com", "empty part"},
		{"-reddit.com", "hyphen"},
		{"reddit-.com", "hyphen"},
		{"reddit!.com", "not valid in a domain"},
		{"reddité.com", "punycode"},
		{strings.Repeat("a", 64) + ".com", "longer than 63"},
	}
	for _, c := range cases {
		got, err := NormalizeDomain(c.in)
		if err == nil {
			t.Errorf("NormalizeDomain(%q) = %q, want an error", c.in, got)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("NormalizeDomain(%q) error %q does not mention %q", c.in, err, c.wantErr)
		}
	}
}

func TestBlockPatterns(t *testing.T) {
	if got := ChromiumBlockPattern("reddit.com"); got != "reddit.com" {
		t.Errorf("chromium pattern = %q, want the bare host", got)
	}
	if got, want := FirefoxBlockPattern("reddit.com"), "*://*.reddit.com/*"; got != want {
		t.Errorf("firefox pattern = %q, want %q", got, want)
	}
}

func domainConfig(names ...string) Config {
	c := Config{}
	for _, n := range names {
		c.Domains = append(c.Domains, Domain{Name: n})
	}
	return c
}

func TestBlockedAndInactiveDomains(t *testing.T) {
	c := domainConfig("reddit.com", "twitter.com")
	c.Domains[1].Disabled = true

	if got := c.BlockedDomains(); len(got) != 1 || got[0] != "reddit.com" {
		t.Errorf("BlockedDomains = %v, want just reddit.com", got)
	}
	if got := c.InactiveDomains(); len(got) != 1 || got[0] != "twitter.com" {
		t.Errorf("InactiveDomains = %v, want just twitter.com", got)
	}
	if got := c.ManagedDomains(); len(got) != 2 {
		t.Errorf("ManagedDomains = %v, want both", got)
	}
}

// TestBlockedDomainsNormalizesAndDedupes: the list is what gets written to the
// browsers, so it has to be canonical and free of duplicates however the file was
// written by hand.
func TestBlockedDomainsNormalizesAndDedupes(t *testing.T) {
	c := domainConfig("https://www.Reddit.com/r/x", "reddit.com.", "REDDIT.COM")
	got := c.BlockedDomains()
	if len(got) != 1 || got[0] != "reddit.com" {
		t.Errorf("BlockedDomains = %v, want exactly [reddit.com]", got)
	}
}

func TestCoveredBy(t *testing.T) {
	c := domainConfig("reddit.com")

	if parent, ok := c.CoveredBy("old.reddit.com"); !ok || parent != "reddit.com" {
		t.Errorf("CoveredBy(old.reddit.com) = %q, %v; want reddit.com, true", parent, ok)
	}
	if parent, ok := c.CoveredBy("reddit.com"); !ok || parent != "reddit.com" {
		t.Errorf("a listed domain covers itself; got %q, %v", parent, ok)
	}
	// Not a subdomain, just a suffix in string terms - must not match.
	if _, ok := c.CoveredBy("notreddit.com"); ok {
		t.Error("notreddit.com is not a subdomain of reddit.com")
	}
	if _, ok := c.CoveredBy("twitter.com"); ok {
		t.Error("twitter.com is unrelated")
	}
	// A switched-off entry blocks nothing, so it cannot cover anything.
	c.Domains[0].Disabled = true
	if _, ok := c.CoveredBy("old.reddit.com"); ok {
		t.Error("a disabled domain should not count as covering a subdomain")
	}
}

func TestCovers(t *testing.T) {
	c := domainConfig("old.reddit.com", "new.reddit.com", "twitter.com")
	got := c.Covers("reddit.com")
	if len(got) != 2 {
		t.Fatalf("Covers(reddit.com) = %v, want the two reddit subdomains", got)
	}
	for _, g := range got {
		if !strings.HasSuffix(g, ".reddit.com") {
			t.Errorf("unexpected entry %q", g)
		}
	}
}

func TestAddDomain(t *testing.T) {
	var c Config

	host, changed, err := c.AddDomain("https://www.Reddit.com/r/x")
	if err != nil || !changed || host != "reddit.com" {
		t.Fatalf("AddDomain = %q, %v, %v", host, changed, err)
	}
	if len(c.Domains) != 1 || c.Domains[0].Name != "reddit.com" {
		t.Errorf("stored as %+v, want the normalized host", c.Domains)
	}

	// Adding it again is a no-op, not an error.
	if _, changed, err := c.AddDomain("reddit.com"); err != nil || changed {
		t.Errorf("re-adding = %v, %v; want no change and no error", changed, err)
	}

	// A subdomain of something already blocked tightens nothing, so it is refused.
	if _, _, err := c.AddDomain("old.reddit.com"); err == nil {
		t.Error("adding a covered subdomain should be refused")
	} else if !strings.Contains(err.Error(), "already covered by reddit.com") {
		t.Errorf("error %q should name the covering domain", err)
	}

	// Re-enabling a switched-off entry counts as a change.
	c.Domains[0].Disabled = true
	if _, changed, err := c.AddDomain("reddit.com"); err != nil || !changed {
		t.Errorf("re-enabling = %v, %v; want a change", changed, err)
	}
	if c.Domains[0].Disabled {
		t.Error("re-adding should switch it back on")
	}
}

func TestSetDomainEnabled(t *testing.T) {
	c := domainConfig("reddit.com")

	if host, ok := c.SetDomainEnabled("https://www.reddit.com/", false); !ok || host != "reddit.com" {
		t.Fatalf("SetDomainEnabled = %q, %v", host, ok)
	}
	if !c.Domains[0].Disabled {
		t.Error("domain should be switched off")
	}
	if len(c.Domains) != 1 {
		t.Error("switching off must keep it in the list so it can be offered back")
	}
	if _, ok := c.SetDomainEnabled("twitter.com", false); ok {
		t.Error("an unlisted domain should report false")
	}
}

func TestValidateDomains(t *testing.T) {
	if err := domainConfig("reddit.com", "twitter.com").Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := domainConfig("reddit.com", "https://www.Reddit.com/").Validate(); err == nil {
		t.Error("the same domain twice in different spellings should be rejected")
	} else if !strings.Contains(err.Error(), "more than once") {
		t.Errorf("error %q should say it is duplicated", err)
	}
	if err := domainConfig("*").Validate(); err == nil {
		t.Error("a wildcard entry should be rejected")
	}
}

// TestBlockGovernsDomain covers the schedule wiring: a block narrows a domain to
// its windows, and comparison is on normalized hosts so the block and the list
// agree however either was typed.
func TestBlockGovernsDomain(t *testing.T) {
	b := Block{ID: "work", Domains: []string{"https://www.Reddit.com/"}}
	if !b.GovernsDomain("reddit.com") {
		t.Error("block should govern reddit.com however it was written")
	}
	if b.GovernsDomain("twitter.com") {
		t.Error("block should not govern an unrelated domain")
	}
	// Naming only extensions means the block governs no domains at all.
	if (Block{ID: "x", Extensions: []string{"sieve"}}).GovernsDomain("reddit.com") {
		t.Error("a block that names only extensions must not govern domains")
	}
	// Naming neither governs everything, which is what a pre-domains config means.
	if !(Block{ID: "all"}).GovernsDomain("reddit.com") {
		t.Error("a block naming nothing should govern every domain")
	}
}

// TestActiveAtResolvesDomains is the end-to-end schedule behaviour: a domain
// under a block is only blocked inside its windows, and an ungoverned domain is
// blocked around the clock.
func TestActiveAtResolvesDomains(t *testing.T) {
	c := domainConfig("reddit.com", "gambling.example")
	c.Blocks = []Block{{
		ID:      "work",
		Domains: []string{"reddit.com"},
		Windows: []Window{{Days: []string{"mon"}, Start: "09:00", End: "17:00"}},
	}}

	inside := c.ActiveAt(at(17, 10, 0)).BlockedDomains()
	if len(inside) != 2 {
		t.Errorf("inside the window both domains should be blocked, got %v", inside)
	}
	outside := c.ActiveAt(at(17, 20, 0)).BlockedDomains()
	if len(outside) != 1 || outside[0] != "gambling.example" {
		t.Errorf("outside the window only the ungoverned domain should be blocked, got %v", outside)
	}
	// The one that dropped out must be reported as inactive so ApplyDomains prunes it.
	if stale := c.ActiveAt(at(17, 20, 0)).InactiveDomains(); len(stale) != 1 || stale[0] != "reddit.com" {
		t.Errorf("InactiveDomains = %v, want reddit.com so the block is lifted", stale)
	}
}

func TestActiveAtDoesNotMutateDomains(t *testing.T) {
	c := domainConfig("reddit.com")
	c.Blocks = []Block{{ID: "work", Domains: []string{"reddit.com"},
		Windows: []Window{{Days: []string{"mon"}, Start: "09:00", End: "17:00"}}}}

	_ = c.ActiveAt(at(17, 20, 0)) // outside the window
	if got := c.BlockedDomains(); len(got) != 1 {
		t.Errorf("ActiveAt mutated the receiver's domains: %v", got)
	}
}

// TestActiveSignatureNoticesDomainBoundary: the service re-applies on a change to
// this string, so a domain window opening or closing has to move it.
func TestActiveSignatureNoticesDomainBoundary(t *testing.T) {
	c := domainConfig("reddit.com")
	c.Blocks = []Block{{ID: "work", Domains: []string{"reddit.com"},
		Windows: []Window{{Days: []string{"mon"}, Start: "09:00", End: "17:00"}}}}

	if in, out := c.ActiveSignature(at(17, 10, 0)), c.ActiveSignature(at(17, 20, 0)); in == out {
		t.Errorf("signature did not change across a domain boundary: %q", in)
	}
}

func TestValidateBlockDomainReference(t *testing.T) {
	c := domainConfig("reddit.com")
	c.Blocks = []Block{{ID: "work", Domains: []string{"twitter.com"}}}
	if err := c.Validate(); err == nil {
		t.Error("a block referencing a domain not in the list should be rejected")
	} else if !strings.Contains(err.Error(), "not in the domains list") {
		t.Errorf("error %q should explain the missing entry", err)
	}
}

// TestDomainsOmittedWhenEmpty keeps trusted copies written before domains existed
// comparing equal after the upgrade.
func TestDomainsOmittedWhenEmpty(t *testing.T) {
	canon, err := Config{Extensions: []Extension{{Name: "sieve"}}}.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canon), "domains") {
		t.Errorf("canonical encoding mentions domains when there are none:\n%s", canon)
	}
}

// TestLockedBlockProtectsDomains: a locked block cannot have its domain list
// edited, or the lock would be trivially escapable by removing the site from it.
func TestLockedBlockProtectsDomains(t *testing.T) {
	now := time.Now()
	until := now.Add(24 * time.Hour).Format(time.RFC3339)

	current := domainConfig("reddit.com")
	current.Blocks = []Block{{ID: "focus", Domains: []string{"reddit.com"}, LockedUntil: until}}

	proposed := domainConfig("reddit.com")
	proposed.Blocks = []Block{{ID: "focus", Domains: []string{}, LockedUntil: until}}

	if err := CheckLockedBlocks(current, proposed, now); err == nil {
		t.Error("emptying a locked block's domain list should be refused")
	}
}
