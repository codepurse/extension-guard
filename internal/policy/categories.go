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
	// Settings are the browser settings the category turns on, on top of - or
	// instead of - any rules it names. It exists because one whole category is
	// not a list at all: see "adult" below, where the honest answer is a
	// filtering resolver somebody else maintains, not hostnames compiled into
	// this binary.
	//
	// A setting is applied exactly as `guard harden` would apply it, and never
	// in the weakening direction - ApplyCategory skips one that would filter
	// less than what is already in force. Applying a category costs no
	// password, so it must not become the way protection is lowered.
	Settings []CategorySetting
}

// CategorySetting is one hardening knob a category turns on, with the level it
// asks for. Level carries a SafeSearch level or a resolver id, and is empty for
// a knob that takes neither - the same values `guard harden -level` accepts,
// since Config.SetKnob is what applies it.
type CategorySetting struct {
	Knob  string
	Level string
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
	// The one category that is not a list, and the reason Category has a
	// Settings field at all.
	//
	// What counts as adult content is a question with millions of answers that
	// change daily. A few dozen hostnames compiled into this binary would be a
	// promise the program cannot keep: the block would look like it worked
	// while the next site along loaded fine, which is worse than not offering
	// the category, because the user stops looking. So this ships no domains.
	// It turns on the two settings that put the classification somewhere it is
	// actually maintained.
	//
	// No application rules either, and that is not an omission. This content is
	// reached through a browser; naming executables here would be guessing at
	// software nobody has verified, and a shipped rule is applied by somebody
	// who has not looked at it - the same reason window-title rules are refused.
	//
	// private-browsing is deliberately not one of the settings. It is the right
	// knob for a locked extension, which cannot load in an Incognito window -
	// but both settings here are browser policy, and browser policy applies to
	// Incognito too. Adding it would take away a feature this category does not
	// need, under a switch that costs no password.
	"adult": {
		ID:    "adult",
		Label: "Adult content",
		Note: "This category ships no list of sites, on purpose. It turns on filtered DNS and " +
			"SafeSearch instead, so what counts as adult content is answered by a service that " +
			"maintains that answer continuously, rather than by a few hostnames compiled into " +
			"this program that would be out of date the week it shipped. Read both settings' " +
			"own notes before turning it on, because each has a real cost: filtered DNS is " +
			"pinned closed, which is what makes it hard to bypass and also what breaks " +
			"captive-portal wifi and a company network's internal names, and SafeSearch is not " +
			"enforced in Firefox or Zen at all because Mozilla ships no policy for it. Neither " +
			"setting reaches a non-browser application, or a browser the guard writes no policy " +
			"for - run `guard browsers` for those. There is no block to schedule or lock here; " +
			"these are settings, and they are on until somebody turns them off with the password.",
		Settings: []CategorySetting{
			{Knob: KnobDNSFilter, Level: ResolverCloudflareFamily},
			{Knob: KnobSafeSearch, Level: SafeSearchStrict},
		},
	},

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
	// inside Chrome, Edge, Brave, Firefox and Zen by writing policy those five
	// read, and a browser that reads none of it carries no locked extension and
	// honours no blocked site. See browsers.go, which finds them.
	"browsers": {
		ID:    "browsers",
		Label: "Unmanaged browsers",
		Note: "This is the bypass that makes every other block optional - a browser the guard " +
			"writes no policy for has none of the locked extensions and none of the blocked sites. " +
			"It covers browsers that install under their own executable name, and it cannot cover " +
			"one shipping as chrome.exe or firefox.exe - a raw Chromium build, ungoogled-chromium, " +
			"Cent Browser - because blocking those by name would take the real Chrome or Firefox " +
			"out with them. Zen is not here for the opposite reason: the guard writes policy Zen " +
			"reads, so it is filtered like Firefox rather than blocked. " +
			"Tor Browser is one of those, and is covered by tor.exe instead: the " +
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
			//
			// The guard filters these when they are installed: each one is asked
			// what it calls itself and written policy under that name (see
			// gecko.go), so they are no longer holes. They stay in the category
			// because blocking is the stronger answer and remains a coherent thing
			// to want - a filtered browser still runs, and somebody who does not
			// want a second browser on the machine at all can still say so. What
			// they are not any more is the *only* answer.
			//
			// Zen is the one that left, and had to: it is a browser the guard
			// writes policy for whether or not it is installed, and
			// validateCategory refuses a shipped rule naming one of those,
			// because blocking it would take the filtering with it.
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
			// zen-browser.app is not here for the same reason zen.exe is not above:
			// there is nothing to stop anyone installing, since what they would
			// install is filtered.
			"opera.com", "vivaldi.com", "torproject.org",
			"librewolf.net", "waterfox.net", "palemoon.org",
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
	if len(cat.Apps) == 0 && len(cat.Domains) == 0 && len(cat.Settings) == 0 {
		return fmt.Errorf("category %q covers nothing", id)
	}
	if err := validateCategorySettings(id, cat); err != nil {
		return err
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

// validateCategorySettings holds a category's browser settings to the same bar
// its rules are held to: the knob has to exist, and the level has to be one that
// knob accepts.
//
// It checks by applying the setting to a throwaway config rather than by
// repeating SetKnob's switch here. A knob that grows a new level, or a resolver
// that leaves the table, would otherwise leave a stale copy of the rules in this
// file quietly passing something SetKnob refuses - and the failure would surface
// on a user's machine, halfway through applying a category, rather than in the
// test that holds the catalog.
func validateCategorySettings(id string, cat Category) error {
	seen := make(map[string]bool, len(cat.Settings))
	for _, st := range cat.Settings {
		knob := strings.ToLower(strings.TrimSpace(st.Knob))
		if _, ok := LookupKnob(knob); !ok {
			return fmt.Errorf("category %q: %q is not a browser setting", id, st.Knob)
		}
		if seen[knob] {
			return fmt.Errorf("category %q sets %q twice", id, knob)
		}
		seen[knob] = true
		var probe Config
		if _, err := probe.SetKnob(knob, true, st.Level); err != nil {
			return fmt.Errorf("category %q: %s cannot be set to %q: %w", id, knob, st.Level, err)
		}
	}
	return nil
}

// BlocksAnything reports whether the category names rules at all, as opposed to
// being settings only. It decides the words used about it - a category with no
// rules is turned "on" rather than "blocked" - and it decides the real thing
// underneath that wording: there is no block to put on a schedule or to lock.
func (c Category) BlocksAnything() bool {
	return len(c.Apps) > 0 || len(c.Domains) > 0
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
	// Settings are the browser settings this call turned on, named as the
	// Browser settings section names them. A setting already in force is not
	// listed here, for the same reason an app already blocked is not.
	Settings []string
	Skipped  []string // entries already covered some other way, with the reason
	Block    Block    // the block governing the category, as it now stands
	// NewBlock is false when the category was already present and this call only
	// topped it up.
	NewBlock bool
}

// Changed reports whether applying the category altered the config at all.
func (r CategoryResult) Changed() bool {
	return len(r.Apps) > 0 || len(r.Domains) > 0 || len(r.Settings) > 0 || r.NewBlock
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

	// Settings go through SetKnob, the same path `guard harden` takes, so a
	// category cannot put the config into a state the CLI could not.
	for _, st := range cat.Settings {
		// Already in force is left exactly as it is, and a weakening is refused
		// outright. Applying a category costs no password; if it could lower a
		// SafeSearch level, it would be the way around the gate HardenWeakens
		// exists to hold. hasSetting is what makes "already in force" mean at
		// least as strong, so neither case can quietly downgrade the machine.
		if c.hasSetting(st) || c.HardenWeakens(st.Knob, st.Level) {
			continue
		}
		changed, err := c.SetKnob(st.Knob, true, st.Level)
		if err != nil {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s (%v)", settingLabel(st), err))
			continue
		}
		if changed {
			res.Settings = append(res.Settings, settingLabel(st))
		}
	}

	// A category that names no rules has no block to create: there is nothing
	// for a block to govern, and its settings are already applied by the time we
	// reach here. This is the "adult" shape - browser settings and no list - and
	// without this line it would fail as "nothing could be added" having just
	// changed the machine.
	if !cat.BlocksAnything() {
		return res, nil
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
	// EntrySetting is a browser setting rather than a thing being blocked. It is
	// a distinct kind because the state word differs - a setting is "on", not
	// "blocked" - and the window and the CLI both key that wording off it.
	EntrySetting = "setting"
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

// CategoryEntries lists everything a category covers - settings first, then
// apps, then sites, in catalog order. Each entry says whether the config already holds it.
//
// An entry that cannot normalize is still listed, marked absent, rather than
// dropped: a catalog line the guard would refuse is a bug worth seeing in the
// one place that shows the catalog, not one worth hiding from the person who
// would have to explain why the count did not add up.
func (c Config) CategoryEntries(cat Category) []CategoryEntry {
	out := make([]CategoryEntry, 0, len(cat.Settings)+len(cat.Apps)+len(cat.Domains))
	// Settings first. A category holding both is turning something on before it
	// blocks anything, and read in that order the rules underneath make sense as
	// the narrower half of one decision.
	for _, st := range cat.Settings {
		out = append(out, CategoryEntry{
			Kind:    EntrySetting,
			Label:   settingLabel(st),
			Value:   strings.ToLower(strings.TrimSpace(st.Knob)),
			Detail:  settingDetail(st),
			Present: c.hasSetting(st),
		})
	}
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
	for _, st := range cat.Settings {
		if !c.hasSetting(st) {
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

// hasSetting reports whether a category's browser setting is already in force,
// at least as strongly as the category asks for. It is the settings half of
// hasApp and hasDomain, and it decides both what CategoryMissing counts and what
// ApplyCategory leaves alone.
//
// "At least as strongly" rather than "exactly" is what stops a category undoing
// a choice the user already made. A machine already on strict SafeSearch is not
// topped up by a category asking for strict. The case that really matters is the
// resolver: a machine pinned to some other filtering resolver is left on it,
// because the user picked that one, and swapping it for whichever this program
// happens to name first would be a lateral move dressed up as protection - taken
// without a password, on a switch that is meant only ever to add.
func (c Config) hasSetting(st CategorySetting) bool {
	h := c.Hardened()
	switch strings.ToLower(strings.TrimSpace(st.Knob)) {
	case KnobPrivateBrowsing:
		return h.PrivateBrowsing
	case KnobSafeSearch:
		cur, on := h.SafeSearchOn()
		if !on {
			return false
		}
		want, err := NormalizeSafeSearch(st.Level)
		if err != nil || want == "" {
			want = SafeSearchStrict
		}
		return safeSearchRank(cur) >= safeSearchRank(want)
	case KnobDNSFilter:
		_, on := h.DNSFilterOn()
		return on
	}
	return false
}

// settingLabel names a setting the way the Browser settings section names it, so
// the two places cannot end up calling one switch by two names.
func settingLabel(st CategorySetting) string {
	if k, ok := LookupKnob(st.Knob); ok {
		return k.Label
	}
	return st.Knob
}

// settingDetail says what the setting will actually be set to, for the Detail
// column. For a resolver that means naming who does the filtering and what they
// claim to filter, in their words: the guard classifies nothing here, and who is
// answering is the whole substance of the setting and the one fact a reader
// cannot guess from the knob's name.
func settingDetail(st CategorySetting) string {
	switch strings.ToLower(strings.TrimSpace(st.Knob)) {
	case KnobSafeSearch:
		level, err := NormalizeSafeSearch(st.Level)
		if err != nil || level == "" {
			level = SafeSearchStrict
		}
		return level
	case KnobDNSFilter:
		id, err := NormalizeDNSFilter(st.Level)
		if err != nil || id == "" {
			id = ResolverCloudflareFamily
		}
		if r, ok := LookupResolver(id); ok {
			return r.Label + " - " + r.Covers
		}
		return id
	}
	return ""
}

// CategoryApplied reports whether a category is in force, which is not the same
// question as whether its block exists.
//
// A category that names rules is in force when its block is there: that block is
// what enforces them, and it is what remove-block lifts. A category that names
// only settings has no block at all, so the only thing "applied" can mean for it
// is that every setting it asks for is on. Without the distinction the adult
// category would read "available" forever, having been applied.
func (c Config) CategoryApplied(cat Category) bool {
	if cat.BlocksAnything() {
		_, ok := c.Block(cat.ID)
		return ok
	}
	if len(cat.Settings) == 0 {
		return false
	}
	for _, st := range cat.Settings {
		if !c.hasSetting(st) {
			return false
		}
	}
	return true
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
