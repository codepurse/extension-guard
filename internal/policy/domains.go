package policy

import (
	"fmt"
	"strings"
)

// Domain blocking uses each browser's enterprise URL-filter policy rather than
// anything below the browser:
//
//   - Chromium (Chrome, Edge, Brave): URLBlocklist. A bare hostname blocks that
//     host, every subdomain, and every scheme and path under it - so "reddit.com"
//     covers www.reddit.com, old.reddit.com and https://reddit.com/r/whatever
//     with one entry.
//   - Firefox: WebsiteFilter/Block, which takes match patterns. "*://*.reddit.com/*"
//     covers the bare host and its subdomains the same way.
//
// Why here and not the hosts file: a hosts entry is resolved by the OS, and both
// Chrome and Firefox can be configured to use DNS-over-HTTPS, which bypasses the
// OS resolver entirely - the block would silently stop working. A policy is
// enforced inside the browser, above DNS, so DoH does not get around it. It also
// lands in HKLM\SOFTWARE\Policies, which the guard's tamper watcher already
// watches, so a deleted key is restored within milliseconds for free.
//
// What this does not cover, stated plainly: a browser the guard does not support,
// and any non-browser application. Those need enforcement below the browser,
// which is the app/network work still to come.
//
// Writing the policy is only half of it: a browser has to re-read it. Chromium is
// nudged into doing that immediately (see gprefresh_windows.go), and then applies
// the change to the next navigation - an already-open tab keeps showing what it
// loaded until it is reloaded. Firefox reads its policies only at startup and has
// no reload path, so a change made while it is running waits for the next start,
// which is why the window and the CLI say so when Firefox is open.

// Domain is one blocked site. Name is a hostname; blocking it also blocks every
// subdomain. Disabled keeps it in the list but stops enforcing it, exactly as it
// does for an extension, so the status window can offer it back.
type Domain struct {
	Name     string `json:"name"`
	Disabled bool   `json:"disabled,omitempty"`
	// Source records where the domain came from, exactly as App.Source does for a
	// rule - "category:social" for one a category added, empty for one added by
	// hand. See App.Source for why it is provenance only and why it is omitempty.
	Source string `json:"source,omitempty"`
}

// maxDomainEntries is the ceiling Chromium puts on URLBlocklist. Going over it
// does not error - the browser silently ignores the excess, which would be a
// block the user believes in and does not have.
const maxDomainEntries = 1000

// NormalizeDomain reduces what a person would reasonably type to the bare
// hostname the policies want: it accepts "https://Reddit.com/r/x", "www.reddit.com",
// "reddit.com:443" and "reddit.com." and returns "reddit.com" for all of them.
//
// A leading "www." is dropped on purpose. Someone entering www.reddit.com means
// Reddit, and keeping the prefix would block only that host and its subdomains,
// quietly leaving old.reddit.com reachable.
func NormalizeDomain(s string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(s))
	if h == "" {
		return "", fmt.Errorf("empty domain")
	}
	// Scheme, then any path, query or fragment.
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	h = strings.TrimPrefix(h, "//")
	// Cut the path and everything after it. Only "/" is used as the boundary: a
	// "?" with no path before it is not a query string in any address a person
	// would paste, it is a stray character in the hostname, and the checks below
	// should say so rather than silently truncate to something that parses.
	if i := strings.Index(h, "/"); i >= 0 {
		h = h[:i]
	}
	// Credentials and port.
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "www.")

	if h == "" {
		return "", fmt.Errorf("no hostname in %q", s)
	}
	// A lone "*" is a valid Chromium pattern meaning "block every URL". Reaching
	// that by typo would take the whole web out, so it is refused here; blocking
	// everything deliberately deserves its own feature and its own confirmation.
	if strings.ContainsAny(h, "*?#") {
		return "", fmt.Errorf("%q is not a plain domain - enter just the hostname; subdomains are covered automatically and wildcards are not accepted", s)
	}
	if strings.ContainsAny(h, " \t,;") {
		return "", fmt.Errorf("%q looks like more than one domain - add them one at a time", s)
	}
	if !strings.Contains(h, ".") {
		return "", fmt.Errorf("%q is not a domain (no dot) - did you mean %q?", s, h+".com")
	}
	for _, label := range strings.Split(h, ".") {
		if err := checkLabel(label, s); err != nil {
			return "", err
		}
	}
	return h, nil
}

// checkLabel validates one dot-separated part of a hostname.
func checkLabel(label, original string) error {
	if label == "" {
		return fmt.Errorf("%q has an empty part (check the dots)", original)
	}
	if len(label) > 63 {
		return fmt.Errorf("%q has a part longer than 63 characters", original)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("%q has a part starting or ending with a hyphen", original)
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		case r > 127:
			return fmt.Errorf("%q contains non-ASCII characters - use its punycode form (xn--...)", original)
		default:
			return fmt.Errorf("%q contains %q, which is not valid in a domain", original, string(r))
		}
	}
	return nil
}

// ChromiumBlockPattern is the URLBlocklist entry for a normalized host. The bare
// hostname is the whole pattern: Chromium treats it as host-and-subdomains
// across every scheme and path.
func ChromiumBlockPattern(host string) string { return host }

// FirefoxBlockPattern is the WebsiteFilter match pattern for a normalized host.
// "*.host" matches the bare host as well as its subdomains.
func FirefoxBlockPattern(host string) string { return "*://*." + host + "/*" }

// BlockedDomains returns the normalized hostnames to block right now: the
// enabled entries, deduplicated, with anything unparseable left out (Validate
// reports those).
func (c Config) BlockedDomains() []string {
	return c.normalizedDomains(false)
}

// InactiveDomains returns the normalized hostnames that are configured but
// currently switched off - either by their own Disabled flag or because ActiveAt
// resolved them out of a schedule window.
//
// ApplyDomains needs these to prune. Like the extension policies, the URL filter
// is an incremental list, so writing only the active set would leave a domain
// blocked after its window closed.
func (c Config) InactiveDomains() []string {
	return c.normalizedDomains(true)
}

func (c Config) normalizedDomains(wantDisabled bool) []string {
	seen := make(map[string]bool, len(c.Domains))
	out := make([]string, 0, len(c.Domains))
	for _, d := range c.Domains {
		if d.Disabled != wantDisabled {
			continue
		}
		h, err := NormalizeDomain(d.Name)
		if err != nil || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// AnyDomains reports whether any domain is configured at all, enabled or not.
func (c Config) AnyDomains() bool { return len(c.Domains) > 0 }

// HasDomain reports whether the named domain is already in the list, comparing
// normalized forms so "https://www.Reddit.com/" matches "reddit.com".
func (c Config) HasDomain(name string) bool {
	_, ok := c.findDomain(name)
	return ok
}

func (c Config) findDomain(name string) (int, bool) {
	want, err := NormalizeDomain(name)
	if err != nil {
		return 0, false
	}
	for i, d := range c.Domains {
		if h, err := NormalizeDomain(d.Name); err == nil && h == want {
			return i, true
		}
	}
	return 0, false
}

// CoveredBy returns the enabled listed domain that already blocks host - itself,
// or a parent of it - and whether one exists.
//
// This matters because blocking a domain already blocks its subdomains. Someone
// who blocks reddit.com and then adds old.reddit.com has not tightened anything;
// they have added a redundant entry that makes the list harder to read and eats
// one of the slots browsers actually honour.
func (c Config) CoveredBy(host string) (string, bool) {
	want, err := NormalizeDomain(host)
	if err != nil {
		return "", false
	}
	for _, d := range c.Domains {
		if d.Disabled {
			continue
		}
		listed, err := NormalizeDomain(d.Name)
		if err != nil {
			continue
		}
		if want == listed || strings.HasSuffix(want, "."+listed) {
			return listed, true
		}
	}
	return "", false
}

// Covers returns the listed domains that host would make redundant, i.e. the
// entries that are subdomains of it.
func (c Config) Covers(host string) []string {
	want, err := NormalizeDomain(host)
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range c.Domains {
		listed, err := NormalizeDomain(d.Name)
		if err != nil || listed == want {
			continue
		}
		if strings.HasSuffix(listed, "."+want) {
			out = append(out, listed)
		}
	}
	return out
}

// AddDomain adds a domain in normalized form, or re-enables it if it is already
// listed but switched off. It reports the normalized host and whether the config
// changed. A host already covered by a broader listed domain is refused, since
// adding it would tighten nothing.
func (c *Config) AddDomain(name string) (string, bool, error) {
	host, err := NormalizeDomain(name)
	if err != nil {
		return "", false, err
	}
	if parent, ok := c.CoveredBy(host); ok && parent != host {
		return host, false, fmt.Errorf("%s is already covered by %s, which blocks all of its subdomains", host, parent)
	}
	if i, ok := c.findDomain(host); ok {
		if !c.Domains[i].Disabled {
			return host, false, nil // already blocked
		}
		c.Domains[i].Disabled = false
		return host, true, nil
	}
	if len(c.Domains)+1 > maxDomainEntries {
		return "", false, fmt.Errorf("the block list is full (%d domains); browsers ignore entries past that", maxDomainEntries)
	}
	c.Domains = append(c.Domains, Domain{Name: host})
	return host, true, nil
}

// SetDomainEnabled switches one listed domain on or off, leaving it in the list.
// It reports the normalized host and false if no such domain is configured.
func (c *Config) SetDomainEnabled(name string, enabled bool) (string, bool) {
	host, err := NormalizeDomain(name)
	if err != nil {
		return "", false
	}
	i, ok := c.findDomain(host)
	if !ok {
		return host, false
	}
	c.Domains[i].Disabled = !enabled
	return host, true
}

// SetDomainSource stamps provenance on one listed domain, exactly as
// SetAppSource does for a rule, and leaves the decision of whether to stamp to
// the caller for the same reason.
func (c *Config) SetDomainSource(name, source string) bool {
	host, err := NormalizeDomain(name)
	if err != nil {
		return false
	}
	i, ok := c.findDomain(host)
	if !ok {
		return false
	}
	c.Domains[i].Source = strings.TrimSpace(source)
	return true
}

// validateDomains checks the configured list, and is called by Validate.
func (c Config) validateDomains() error {
	seen := make(map[string]bool, len(c.Domains))
	for _, d := range c.Domains {
		host, err := NormalizeDomain(d.Name)
		if err != nil {
			return fmt.Errorf("blocked domain: %w", err)
		}
		if seen[host] {
			return fmt.Errorf("domain %q is listed more than once", host)
		}
		seen[host] = true
	}
	if len(seen) > maxDomainEntries {
		return fmt.Errorf("%d domains configured, more than the %d browsers accept", len(seen), maxDomainEntries)
	}
	return nil
}

// ManagedDomains returns every normalized host this config governs, enabled or
// not. RemoveDomains uses it to clear only entries the guard put there and leave
// any URL filter the machine's owner or an administrator set up untouched.
func (c Config) ManagedDomains() []string {
	seen := make(map[string]bool, len(c.Domains))
	out := make([]string, 0, len(c.Domains))
	for _, d := range c.Domains {
		h, err := NormalizeDomain(d.Name)
		if err != nil || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}
