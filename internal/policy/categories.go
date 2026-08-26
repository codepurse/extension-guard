package policy

import (
	"fmt"
	"sort"
	"strings"
)

// This file holds the built-in categories: curated sets of applications and
// domains that stand for one kind of distraction, so blocking "social media"
// does not mean knowing that Telegram installs as Telegram.exe and that Threads
// lives on threads.net.
//
// A category is not a new thing in the config. It expands, at the moment it is
// added, into the rules and the block that were always available by hand - see
// Config.ApplyCategory. Nothing reads the catalog at enforcement time, which is
// deliberate and is the whole design:
//
//   - The config keeps saying what is blocked. `guard apps` can answer from the
//     file alone, and a config copied to another machine means the same thing
//     there. A category resolved during the sweep would put half the policy in
//     the binary, where the person bound by it cannot read it.
//   - A catalog that widened an existing block on update would be the updater
//     silently changing what the user agreed to. For a tool whose premise is
//     that protection is hard to weaken, quietly making it broader is the same
//     class of surprise pointed the other way.
//
// The cost is that adding an app to a category here does not reach a config that
// already expanded it. That is paid explicitly rather than silently - the rules
// carry their source (see App.Source), so a later refresh can show what the
// catalog has gained and let the user take it.

// Category is one curated set. Apps are stored as rules normalized on use and
// Domains as bare hostnames; both go through the same Add path a typed rule
// does, so nothing here can enter the config in a shape the rest of the guard
// would refuse.
type Category struct {
	ID    string
	Label string
	// Note explains what the category does and does not cover, and is printed
	// when it is added. Categories promise more than they can deliver if nobody
	// says out loud where the gaps are.
	Note    string
	Apps    []App
	Domains []string
}

// SourcePrefix marks a config entry as belonging to a category. See App.Source.
const SourcePrefix = "category:"

// Source is the provenance string stamped on everything this category adds.
func (c Category) Source() string { return SourcePrefix + c.ID }

// Catalog is every built-in category, keyed by id. ValidateCatalog states the
// rules an entry here has to obey, and a test holds this map to them.
//
// Entries are exact executable names, specific vendor folders, and exact
// hostnames. Window-title rules are refused outright: they match a substring of
// whatever a window happens to be called, so "Discord" would take out a browser
// tab reading about Discord, and a catalog entry is applied by someone who has
// not checked what else it hits. A rule that turns out to be wrong when a person
// adds it by hand is a mistake they can see; the same rule shipped to everyone,
// under a block they may have locked, is one they cannot undo until the lock
// expires.
//
// Folder rules are allowed, but only for a specific vendor directory. Games are
// the case they exist for - a launcher whose executable is called client.exe or
// Launcher.exe cannot be named any other way, since blocking those by name would
// hit every unrelated program that ships one (see genericImages). What a folder
// rule must never be is broad: ValidateCatalog requires two directory levels
// below the drive, so C:\Program Files\Rockstar Games\Launcher is fine and
// C:\Games is not.
var Catalog = map[string]Category{
	"social": {
		ID:    "social",
		Label: "Social media",
		Note: "Most social media has no Windows application - Instagram, TikTok, Facebook, X and " +
			"Snapchat are websites, and the Store versions are web pages in a frame. The domain half " +
			"of this category is what actually holds; the applications are the messaging apps that " +
			"really do install.",
		Apps: []App{
			// Discord ships three release channels side by side, and a blocked
			// stable build with Canary still running is a block that did nothing.
			{Kind: AppExe, Value: "Discord.exe", Label: "Discord"},
			{Kind: AppExe, Value: "DiscordPTB.exe", Label: "Discord PTB"},
			{Kind: AppExe, Value: "DiscordCanary.exe", Label: "Discord Canary"},
			{Kind: AppExe, Value: "Telegram.exe", Label: "Telegram"},
			{Kind: AppExe, Value: "Signal.exe", Label: "Signal"},
			{Kind: AppExe, Value: "Viber.exe", Label: "Viber"},
			{Kind: AppExe, Value: "LINE.exe", Label: "LINE"},
			{Kind: AppExe, Value: "WeChat.exe", Label: "WeChat"},
			{Kind: AppExe, Value: "Skype.exe", Label: "Skype"},
		},
		Domains: []string{
			"facebook.com", "messenger.com", "instagram.com", "threads.net",
			"twitter.com", "x.com", "tiktok.com", "snapchat.com",
			"reddit.com", "tumblr.com", "pinterest.com", "bsky.app",
			"mastodon.social", "vk.com", "weibo.com",
			"9gag.com", "imgur.com",
			"discord.com", "telegram.org",
		},
	},

	"games": {
		ID:    "games",
		Label: "Games",
		Note: "Launchers are what this mostly blocks, because most games will not start without " +
			"theirs. A game already installed and started from its own shortcut is not covered " +
			"unless it is named here too - and a Steam library on a second drive is not covered at " +
			"all, since its path is different on every machine. Add those with Add folder.",
		Apps: []App{
			// Launchers first, and they are the leverage: about a dozen of them
			// cover thousands of titles, because a game bought through a store
			// generally will not start without its launcher running. Individual
			// game executables are an endless tail by comparison.
			{Kind: AppExe, Value: "steam.exe", Label: "Steam"},
			{Kind: AppExe, Value: "EpicGamesLauncher.exe", Label: "Epic Games"},
			{Kind: AppExe, Value: "Battle.net.exe", Label: "Battle.net"},
			{Kind: AppExe, Value: "EADesktop.exe", Label: "EA app"},
			{Kind: AppExe, Value: "Origin.exe", Label: "Origin"},
			{Kind: AppExe, Value: "UbisoftConnect.exe", Label: "Ubisoft Connect"},
			{Kind: AppExe, Value: "upc.exe", Label: "Uplay"},
			{Kind: AppExe, Value: "GalaxyClient.exe", Label: "GOG Galaxy"},
			{Kind: AppExe, Value: "RiotClientServices.exe", Label: "Riot Client"},
			{Kind: AppExe, Value: "Amazon Games UI.exe", Label: "Amazon Games"},
			{Kind: AppExe, Value: "itch.exe", Label: "itch.io"},
			{Kind: AppExe, Value: "Hive_Launcher.exe", Label: "Crossplay Launcher"},

			// The two launchers that cannot be named by their executable at all.
			// Google Play Games runs as client.exe and the Rockstar launcher as
			// Launcher.exe - both refused as bare names, and rightly, because
			// dozens of unrelated programs ship a file by each of those names.
			// The default install directory is the only precise handle there is.
			// Rockstar appears under both program-files roots depending on which
			// installer version put it there.
			{Kind: AppFolder, Value: `C:\Program Files\Google\Play Games`, Label: "Google Play Games"},
			{Kind: AppFolder, Value: `C:\Program Files\Rockstar Games\Launcher`, Label: "Rockstar Games Launcher"},
			{Kind: AppFolder, Value: `C:\Program Files (x86)\Rockstar Games\Launcher`, Label: "Rockstar Games Launcher (x86)"},

			{Kind: AppStore, Value: "Microsoft.GamingApp_8wekyb3d8bbwe", Label: "Xbox"},

			// Games named directly, because these are the ones people start from a
			// desktop shortcut without the launcher's window ever appearing.
			{Kind: AppExe, Value: "RobloxPlayerBeta.exe", Label: "Roblox"},
			{Kind: AppExe, Value: "FortniteClient-Win64-Shipping.exe", Label: "Fortnite"},
			{Kind: AppExe, Value: "VALORANT.exe", Label: "Valorant"},
			{Kind: AppExe, Value: "LeagueClient.exe", Label: "League of Legends"},
			{Kind: AppExe, Value: "cs2.exe", Label: "Counter-Strike 2"},
			{Kind: AppExe, Value: "dota2.exe", Label: "Dota 2"},
			{Kind: AppExe, Value: "r5apex.exe", Label: "Apex Legends"},
			{Kind: AppExe, Value: "Overwatch.exe", Label: "Overwatch"},
			{Kind: AppExe, Value: "GTA5.exe", Label: "Grand Theft Auto V"},
			{Kind: AppExe, Value: "GenshinImpact.exe", Label: "Genshin Impact"},
			{Kind: AppExe, Value: "MinecraftLauncher.exe", Label: "Minecraft"},
		},
		// Browser games only. A launcher's own store site is deliberately absent:
		// blocking steampowered.com would cut the Steam client off from the
		// servers it talks to and surface as a string of connection errors rather
		// than as a block, which is a worse experience than not blocking it.
		Domains: []string{
			"roblox.com", "poki.com", "crazygames.com", "coolmathgames.com",
			"miniclip.com", "y8.com", "addictinggames.com", "itch.io",
			"kongregate.com", "armorgames.com", "friv.com",
		},
	},

	// Unlike the other two, this category does not remove a distraction. It
	// closes the hole that makes every other block optional: the guard filters
	// inside Chrome, Edge, Brave and Firefox by writing policy those four read,
	// and a browser that reads none of it carries no locked extension and
	// honours no blocked site. See browsers.go, which finds them.
	"browsers": {
		ID:    "browsers",
		Label: "Unmanaged browsers",
		Note: "This is the bypass that makes every other block optional - a browser the guard " +
			"writes no policy for has none of the locked extensions and none of the blocked sites. " +
			"It covers browsers that install under their own executable name, and it cannot cover " +
			"one shipping as chrome.exe or firefox.exe - a raw Chromium build, ungoogled-chromium, " +
			"Cent Browser - because blocking those by name would take the real Chrome or Firefox " +
			"out with them. Tor Browser is one of those, and is covered by tor.exe instead: the " +
			"window may still open, but with the daemon blocked no page will load. Yandex ships " +
			"browser.exe, too common a name to block by name alone. Internet Explorer is included " +
			"because it is on the machine whether anyone installed it or not; leave that one out if " +
			"some in-house application still opens it. Most entries also block the vendor's download " +
			"page, since blocking the program alone leaves installing it again open. Run " +
			"`guard browsers` for what is actually on this machine, including anything this list " +
			"does not name, and block those by their full path.",
		Apps: []App{
			// Opera and Opera GX are both opera.exe, in their own directories.
			{Kind: AppExe, Value: "opera.exe", Label: "Opera / Opera GX"},
			{Kind: AppExe, Value: "vivaldi.exe", Label: "Vivaldi"},

			// Tor Browser's own executable is firefox.exe, which cannot be named
			// here without blocking Firefox. tor.exe is the daemon it builds its
			// circuit through, and nothing loads without it.
			{Kind: AppExe, Value: "tor.exe", Label: "Tor"},

			// Firefox forks, each under its own name - so unlike Tor these are
			// blocked outright rather than at the network.
			{Kind: AppExe, Value: "zen.exe", Label: "Zen Browser"},
			{Kind: AppExe, Value: "floorp.exe", Label: "Floorp"},
			{Kind: AppExe, Value: "librewolf.exe", Label: "LibreWolf"},
			{Kind: AppExe, Value: "waterfox.exe", Label: "Waterfox"},
			{Kind: AppExe, Value: "palemoon.exe", Label: "Pale Moon"},
			{Kind: AppExe, Value: "basilisk.exe", Label: "Basilisk"},

			// Internet Explorer, which is on the machine whether anybody installed
			// it or not. On Windows 11 iexplore.exe only hands the page to Edge, so
			// blocking it costs nothing there; on Windows 10 it is still a working
			// browser that reads none of the policy the guard writes, which is the
			// case this entry is for. The cost to know about: a legacy in-house
			// application that shells out to iexplore.exe stops working, and on a
			// machine where that matters this is the entry to leave out.
			{Kind: AppExe, Value: "iexplore.exe", Label: "Internet Explorer"},

			// The Chromium forks that arrive bundled with an antivirus or a
			// cleanup tool rather than being sought out, which is why they turn up
			// on a family machine nobody chose to install a second browser on.
			{Kind: AppExe, Value: "AvastBrowser.exe", Label: "Avast Secure Browser"},
			{Kind: AppExe, Value: "AVGBrowser.exe", Label: "AVG Secure Browser"},
			{Kind: AppExe, Value: "CCleanerBrowser.exe", Label: "CCleaner Browser"},

			{Kind: AppExe, Value: "whale.exe", Label: "Naver Whale"},
			{Kind: AppExe, Value: "maxthon.exe", Label: "Maxthon"},
			{Kind: AppExe, Value: "UCBrowser.exe", Label: "UC Browser"},
			{Kind: AppExe, Value: "slimjet.exe", Label: "Slimjet"},
		},
		// Download pages, and only the ones that are certain. A hostname that is
		// subtly wrong blocks nothing while looking in every listing exactly like
		// one that works, so a vendor whose page this could not state with
		// confidence is left out rather than guessed at - the app rule above is
		// what does the work, and this is a second layer, not the feature.
		//
		// The antivirus vendors are deliberately absent even though their browsers
		// are listed: avast.com is where somebody goes for the antivirus, and
		// cutting that off to stop a bundled browser blocks the wrong thing.
		// whale.naver.com rather than naver.com for the same reason - the browser's
		// page, not a portal millions of people use for everything else.
		Domains: []string{
			"opera.com", "vivaldi.com", "torproject.org",
			"librewolf.net", "waterfox.net", "palemoon.org", "zen-browser.app",
			"whale.naver.com", "maxthon.com", "ucweb.com", "slimjet.com",
		},
	},
}

// Minecraft Java is deliberately not covered. It runs as javaw.exe, a shared
// runtime that a great deal of unrelated software starts through - blocking it
// would take out anything else on the machine written in Java. MinecraftLauncher.exe
// above catches the official launcher, which is how most people start it.

// Slack, Teams and Zoom are deliberately not in "social". They are how people
// are reached for work, and a category that quietly cuts someone off from their
// job is one they will turn off entirely rather than narrow. Anyone who wants
// them gone can say so by name.

// catalogFolderDepth is how many directory levels below the drive a folder rule
// in the catalog must name. Two means C:\Program Files\Rockstar Games is the
// shallowest acceptable shape: enough to be one vendor's directory rather than a
// whole program-files root or a bare C:\Games that could hold anything.
const catalogFolderDepth = 2

// ValidateCatalog checks every built-in category against the rules a shipped
// rule has to obey. It is not called at runtime - the catalog is a constant, so
// there is nothing to validate on a user's machine - but it states the rules
// where they can be read next to the data, and a test holds the catalog to them.
//
// The rules exist because a catalog entry is applied by somebody who has not
// looked at it. Everything here is about a rule being no broader than the one
// program it is meant to name.
func ValidateCatalog() error {
	for id, cat := range Catalog {
		if err := validateCategory(id, cat); err != nil {
			return err
		}
	}
	return nil
}

// validateCategory holds one entry to the rules. It is separate from
// ValidateCatalog so a test can hand it a category that is not in the shipped
// catalog and check that the rule actually fires - a guardrail only ever tested
// against data that already passes it is a guardrail nobody has seen work.
func validateCategory(id string, cat Category) error {
	if cat.ID != id {
		return fmt.Errorf("category keyed %q calls itself %q", id, cat.ID)
	}
	if strings.TrimSpace(cat.Label) == "" {
		return fmt.Errorf("category %q has no label", id)
	}
	if len(cat.Apps) == 0 && len(cat.Domains) == 0 {
		return fmt.Errorf("category %q covers nothing", id)
	}
	seen := make(map[string]bool, len(cat.Apps))
	for _, a := range cat.Apps {
		n, err := NormalizeApp(a.Kind, a.Value, a.Label)
		if err != nil {
			return fmt.Errorf("category %q: %q is not a usable rule: %w", id, a.Value, err)
		}
		if seen[n.key()] {
			return fmt.Errorf("category %q lists %q twice", id, a.Value)
		}
		seen[n.key()] = true
		switch n.Kind {
		case AppTitle:
			// Substring matching on whatever a window is called. "Discord"
			// would take out a browser tab reading about Discord.
			return fmt.Errorf("category %q: %q is a window-title rule, which is too broad to ship", id, a.Value)
		case AppFolder:
			if folderDepth(n.Value) < catalogFolderDepth {
				return fmt.Errorf("category %q: folder %q is too broad to ship - name a vendor's own directory", id, a.Value)
			}
		case AppExe:
			// A bare generic name is refused by AddApp, so it could never be
			// applied - catching it here says so at the source rather than
			// leaving a catalog line that silently does nothing.
			if !hasPathSep(n.Value) && GenericImage(n.Value) {
				return fmt.Errorf("category %q: %q is too common a name to block by name alone - use a folder rule", id, a.Value)
			}
			// No shipped rule may name a browser the guard manages. The
			// browsers category is the reason this rule is here: Tor Browser
			// ships its executable as firefox.exe and LibreWolf did not always
			// use its own name, so the tempting line to write in that category
			// is the one that closes the machine's real Firefox. A user may
			// still block chrome.exe by hand - that is a coherent thing to
			// want - but nobody should be able to do it by accepting a
			// category, least of all under a block they then lock.
			if ClassifyBrowser(n.Value) != "" {
				return fmt.Errorf("category %q: %q is a browser the guard manages - blocking it would take the filtering with it", id, a.Value)
			}
		}
	}
	hosts := make(map[string]bool, len(cat.Domains))
	for _, d := range cat.Domains {
		host, err := NormalizeDomain(d)
		if err != nil {
			return fmt.Errorf("category %q: domain %q is not usable: %w", id, d, err)
		}
		if hosts[host] {
			return fmt.Errorf("category %q lists %q twice", id, host)
		}
		hosts[host] = true
	}
	return nil
}

// folderDepth counts the directory levels a path names below its drive, so
// C:\Program Files\Google\Play Games is three and C:\Games is one.
func folderDepth(p string) int {
	p = trimTrailingSep(normalizeWinPath(p))
	if i := strings.Index(p, `\`); i >= 0 {
		p = p[i+1:]
	} else {
		return 0
	}
	n := 0
	for _, seg := range strings.Split(p, `\`) {
		if strings.TrimSpace(seg) != "" {
			n++
		}
	}
	return n
}

// CategoryIDs lists the catalog in a stable order.
func CategoryIDs() []string {
	ids := make([]string, 0, len(Catalog))
	for id := range Catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// LookupCategory finds a category by id, case-insensitively.
func LookupCategory(id string) (Category, bool) {
	c, ok := Catalog[strings.ToLower(strings.TrimSpace(id))]
	return c, ok
}

// CategoryResult reports what applying a category did, so the caller can tell
// the user what actually changed rather than claiming the whole list.
type CategoryResult struct {
	Apps    []string // rules newly blocked
	Domains []string // domains newly blocked
	Skipped []string // entries already covered some other way, with the reason
	Block   Block    // the block governing the category, as it now stands
	// NewBlock is false when the category was already present and this call only
	// topped it up.
	NewBlock bool
}

// Changed reports whether applying the category altered the config at all.
func (r CategoryResult) Changed() bool {
	return len(r.Apps) > 0 || len(r.Domains) > 0 || r.NewBlock
}

// ApplyCategory expands a category into the config: every app and domain it
// names is added and stamped with its source, and a block governing exactly
// those entries is created.
//
// The block is created with no windows and no limit, which means enforced around
// the clock - so this only ever adds protection, and costs the same admin and no
// password that block-app and block-domain do. Putting the category on a
// schedule afterwards is a separate step, and that one takes the password,
// because it is the step that narrows.
//
// Re-applying is safe and is how a category is topped up: entries already
// present are left exactly as they are, and only what is missing is added.
// Widening a block that already exists - even a locked one - is allowed for the
// same reason blocking a new app is: it strengthens what the user committed to.
//
// An entry the config already covers some other way is skipped and reported
// rather than failing the whole category. One folder rule that happens to
// contain Telegram should not stop the other eighteen entries being applied.
func (c *Config) ApplyCategory(cat Category) (CategoryResult, error) {
	res := CategoryResult{}

	var appValues []string
	for _, a := range cat.Apps {
		// Asked before adding, because afterwards the two are indistinguishable.
		// A rule the user blocked by hand stays theirs: a category that claimed it
		// would be claiming the right to remove it on a later refresh, and taking
		// away a block somebody set deliberately is precisely the move this whole
		// program exists to make hard.
		mine := !c.hasApp(a.Kind, a.Value)
		stored, changed, err := c.AddApp(a.Kind, a.Value, a.Label)
		if err != nil {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s (%v)", a.Value, err))
			continue
		}
		if mine {
			c.SetAppSource(stored.Kind, stored.Value, cat.Source())
		}
		appValues = append(appValues, stored.Value)
		if changed {
			res.Apps = append(res.Apps, stored.Display())
		}
	}

	var domainValues []string
	for _, d := range cat.Domains {
		mine := !c.hasDomain(d)
		host, changed, err := c.AddDomain(d)
		if err != nil {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s (%v)", d, err))
			continue
		}
		if mine {
			c.SetDomainSource(host, cat.Source())
		}
		domainValues = append(domainValues, host)
		if changed {
			res.Domains = append(res.Domains, host)
		}
	}

	if len(appValues) == 0 && len(domainValues) == 0 {
		return res, fmt.Errorf("nothing in the %s category could be added", cat.ID)
	}

	if existing, ok := c.Block(cat.ID); ok {
		merged := existing
		merged.Apps = mergeStrings(existing.Apps, appValues)
		merged.Domains = mergeStrings(existing.Domains, domainValues)
		if !c.ReplaceBlock(merged) {
			return res, fmt.Errorf("block %q went missing while updating it", cat.ID)
		}
		res.Block = merged
		return res, nil
	}

	block := Block{
		ID:      cat.ID,
		Label:   cat.Label,
		Apps:    appValues,
		Domains: domainValues,
	}
	if err := c.AddBlock(block); err != nil {
		return res, err
	}
	res.Block, res.NewBlock = block, true
	return res, nil
}

// The kinds of thing a category covers, as CategoryEntry reports them.
const (
	EntryApp  = "app"
	EntrySite = "site"
)

// CategoryEntry is one thing a category covers, resolved against a config so the
// caller can show what blocking it would actually change.
//
// Present is the part that matters. A user asked to accept twenty-eight blocks
// at once deserves to see which of them are already in place, otherwise the list
// reads as twenty-eight new restrictions when it may be three. It is also what
// makes the list honest after a top-up, where most of it is old news.
type CategoryEntry struct {
	Kind  string // EntryApp or EntrySite
	Label string // what to show: an app's friendly name, or the hostname
	Value string // the rule's stored value, for a caller that needs to act on it
	// Detail says what the entry actually covers, in the words App.Summary
	// already uses everywhere else - "steam.exe, wherever it is installed",
	// "every .exe in C:\Program Files\Google\Play Games", "Store app ...".
	//
	// A list of friendly names alone would hide the difference between blocking
	// one executable and blocking a whole directory, and that difference is the
	// reason there are four kinds of rule. Somebody reading this list to decide
	// whether to accept it needs to see which is which.
	Detail  string
	Present bool // already in the config, in whatever state
}

// CategoryEntries lists everything a category covers, apps first and then sites,
// in catalog order. Each entry says whether the config already holds it.
//
// An entry that cannot normalize is still listed, marked absent, rather than
// dropped: a catalog line the guard would refuse is a bug worth seeing in the
// one place that shows the catalog, not one worth hiding from the person who
// would have to explain why the count did not add up.
func (c Config) CategoryEntries(cat Category) []CategoryEntry {
	out := make([]CategoryEntry, 0, len(cat.Apps)+len(cat.Domains))
	for _, a := range cat.Apps {
		label, value, detail := strings.TrimSpace(a.Label), a.Value, ""
		if n, err := NormalizeApp(a.Kind, a.Value, a.Label); err == nil {
			value, detail = n.Value, n.Summary()
			if label == "" {
				label = n.Display()
			}
		}
		if label == "" {
			label = a.Value
		}
		out = append(out, CategoryEntry{
			Kind:    EntryApp,
			Label:   label,
			Value:   value,
			Detail:  detail,
			Present: c.hasApp(a.Kind, a.Value),
		})
	}
	for _, d := range cat.Domains {
		host := d
		if h, err := NormalizeDomain(d); err == nil {
			host = h
		}
		out = append(out, CategoryEntry{
			Kind:    EntrySite,
			Label:   host,
			Value:   host,
			Detail:  "and every subdomain",
			Present: c.hasDomain(d),
		})
	}
	return out
}

// CategoryMissing reports how many of a category's entries the config does not
// already hold. Zero means applying it would change nothing, which is what lets
// the status window offer "Block" or "Top up" rather than a button that may
// silently do neither.
//
// A disabled entry counts as held. It is in the list, the user switched it off
// themselves, and a category has no business switching it back on behind them -
// re-applying leaves it exactly as it is, so promising an addition here would be
// a lie about what the button does.
func (c Config) CategoryMissing(cat Category) int {
	n := 0
	for _, a := range cat.Apps {
		if !c.hasApp(a.Kind, a.Value) {
			n++
		}
	}
	for _, d := range cat.Domains {
		if !c.hasDomain(d) {
			n++
		}
	}
	return n
}

// hasApp reports whether a rule is already listed, in whatever state. It looks
// past normalization failures on purpose: a value that cannot normalize is not
// in the list under any spelling, and AddApp is about to refuse it anyway.
func (c Config) hasApp(kind, value string) bool {
	n, err := NormalizeApp(kind, value, "")
	if err != nil {
		return false
	}
	_, ok := c.findApp(n.Kind, n.Value)
	return ok
}

// hasDomain reports whether a domain is already listed, in whatever state.
func (c Config) hasDomain(name string) bool {
	host, err := NormalizeDomain(name)
	if err != nil {
		return false
	}
	_, ok := c.findDomain(host)
	return ok
}

// mergeStrings appends the values of add that base does not already hold,
// comparing case-insensitively and keeping the order and spelling of base. A
// block's app list is matched against rule values, which are compared that way
// everywhere else.
func mergeStrings(base, add []string) []string {
	seen := make(map[string]bool, len(base))
	for _, s := range base {
		seen[strings.ToLower(strings.TrimSpace(s))] = true
	}
	out := base
	for _, s := range add {
		k := strings.ToLower(strings.TrimSpace(s))
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

// AppCategories reports, for every app rule that came from a category, which one
// it came from. It is what `guard apps` and the status window group by.
func (c Config) AppCategories() map[string]string {
	out := make(map[string]string)
	for _, a := range c.Apps {
		src := strings.TrimSpace(a.Source)
		if !strings.HasPrefix(src, SourcePrefix) {
			continue
		}
		out[strings.ToLower(a.Kind)+"|"+strings.ToLower(a.Value)] = strings.TrimPrefix(src, SourcePrefix)
	}
	return out
}
