package policy

import "testing"

// The two files this was written against, copied from real installs rather than
// imagined. If a future Gecko release changes the shape, this is the test that
// says so instead of a machine quietly going unmanaged.
const (
	firefoxINI = `; This file is not used. If you modify it and want the application to use
; your modifications, move it under the browser/ subdirectory and start with
; the "-app /path/to/browser/application.ini" argument.
[App]
Vendor=Mozilla
Name=Firefox
RemotingName=firefox
Version=154.0.1
ID={ec8030f7-c20a-464f-9b0e-13a3a9e97384}

[Gecko]
MinVersion=154.0.1
MaxVersion=154.0.1

[XRE]
EnableProfileMigrator=1
`
	zenINI = `[App]
Vendor=Mozilla
Name=Zen
RemotingName=zen
Version=1.21.1b
Profile=zen

[Gecko]
MinVersion=151.0.4
MaxVersion=151.0.4
`
)

func TestAppNameFromINIReadsWhatARealInstallShips(t *testing.T) {
	if got := appNameFromINI([]byte(firefoxINI)); got != "Firefox" {
		t.Errorf("firefox: got %q, want Firefox", got)
	}
	if got := appNameFromINI([]byte(zenINI)); got != "Zen" {
		t.Errorf("zen: got %q, want Zen", got)
	}
}

// The two halves of "is this a Gecko install": the name has to be under [App],
// and the file has to say it is Gecko. Without the second, any program shipping
// an ini file with a Name in it would be handed a policy key of its own.
func TestAppNameFromINIRefusesWhatIsNotAGeckoInstall(t *testing.T) {
	cases := map[string]string{
		"no gecko section":  "[App]\nName=NotABrowser\n",
		"name outside App":  "[Gecko]\nName=Sneaky\nMinVersion=1\n",
		"empty file":        "",
		"no name at all":    "[App]\nVendor=Mozilla\n\n[Gecko]\nMinVersion=1\n",
		"gecko but no name": "[Gecko]\nMinVersion=1\n",
	}
	for what, body := range cases {
		if got := appNameFromINI([]byte(body)); got != "" {
			t.Errorf("%s: got %q, want empty", what, got)
		}
	}
}

// CRLF, comments, blank lines and spacing around the "=" are all shapes a real
// ini comes in, and a parser that only handled the tidy one would drop a browser
// on the machines it was strictest about.
func TestAppNameFromINISurvivesOrdinaryFormatting(t *testing.T) {
	body := "; a comment\r\n\r\n[app]\r\n  Name  =  Floorp  \r\n\r\n[GECKO]\r\nMinVersion=128.0\r\n"
	if got := appNameFromINI([]byte(body)); got != "Floorp" {
		t.Errorf("got %q, want Floorp", got)
	}
}

// The name is read out of a file inside a browser's own directory - which, for a
// per-user install, is a directory the person being filtered can write - and it
// is pasted onto the end of a registry path under HKLM\SOFTWARE\Policies. So
// anything that is not a plain application name is refused rather than cleaned
// up: a separator would have the guard create keys somewhere it never meant to.
func TestGeckoKindForRefusesAnythingThatIsNotAPlainName(t *testing.T) {
	for _, name := range []string{
		"",
		"   ",
		`Fire\fox`,
		"Fire/fox",
		`..\..\Google\Chrome`,
		"Fire\nfox",
		"Fire\x00fox",
		"Zen*",
		"Zen;Firefox",
		"Zen\"",
		"ThisNameIsFarTooLongToBeAnyBrowserThatHasEverShipped",
	} {
		if k, ok := geckoKindFor(name); ok {
			t.Errorf("geckoKindFor(%q) was accepted as %q", name, k)
		}
	}
}

// The accepted shapes, and what they become. The Kind is what the config and the
// status table use, so it is the lowercase identifier; the name keeps its own
// capitalization for the policy key and for prose.
func TestGeckoKindForAcceptsRealBrowserNames(t *testing.T) {
	cases := map[string]Kind{
		"Firefox":     "firefox",
		"Zen":         "zen",
		"LibreWolf":   "librewolf",
		"Waterfox":    "waterfox",
		"Floorp":      "floorp",
		"Tor Browser": "tor-browser",
		"Basilisk-2":  "basilisk-2",
	}
	for name, want := range cases {
		got, ok := geckoKindFor(name)
		if !ok {
			t.Errorf("geckoKindFor(%q) was refused", name)
			continue
		}
		if got != want {
			t.Errorf("geckoKindFor(%q) = %q, want %q", name, got, want)
		}
	}
}
