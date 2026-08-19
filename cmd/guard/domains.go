package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/codepurse/extension-guard/internal/enforce"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
)

// This file holds the commands for the domain block list. They mirror the
// extension toggles deliberately: adding a block only strengthens protection so
// it costs admin and nothing more, while lifting one weakens it and takes the
// password.

// domainsCmd lists the block list and whether each entry is being enforced right
// now. Read-only and admin-free.
func domainsCmd(cfg policy.Config) {
	if len(cfg.Domains) == 0 {
		fmt.Println("no domains blocked; add one with `guard block-domain reddit.com`")
		return
	}
	active := activeNow(cfg)
	blockedNow := make(map[string]bool)
	for _, h := range active.BlockedDomains() {
		blockedNow[h] = true
	}

	fmt.Printf("  %-40s %-9s %s\n", "domain", "state", "note")
	for _, d := range cfg.Domains {
		host, err := policy.NormalizeDomain(d.Name)
		if err != nil {
			fmt.Printf("  %-40s %-9s %v\n", d.Name, "invalid", err)
			continue
		}
		state, note := "blocked", "also covers every subdomain"
		switch {
		case d.Disabled:
			state, note = "off", "switched off"
		case !blockedNow[host]:
			state, note = "idle", "outside its block's window"
		}
		fmt.Printf("  %-40s %-9s %s\n", host, state, note)
	}
}

// blockDomainCmd adds a domain to the block list and enforces it immediately.
// Admin, but no password: it only adds protection, the same gate as
// enable-extension.
func blockDomainCmd(cfg policy.Config, cfgPath, name string) {
	if strings.TrimSpace(name) == "" {
		fmt.Fprintln(os.Stderr, "error: domain required, e.g. `guard block-domain reddit.com`")
		os.Exit(2)
	}
	superseded := cfg.Covers(name)
	host, changed, err := cfg.AddDomain(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if !changed {
		fmt.Printf("%s is already blocked\n", host)
		return
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	fmt.Printf("blocked: %s and every subdomain\n", host)
	if len(superseded) > 0 {
		fmt.Printf("(this now covers %s, which you can drop from the list)\n", strings.Join(superseded, ", "))
	}
	if governed := governingBlocks(cfg, host); governed != "" {
		fmt.Printf("(scheduled by %s, so it is only enforced during those windows)\n", governed)
	}
}

// unblockDomainCmd stops enforcing a domain, keeping it in the list so it can be
// turned back on. That weakens protection, so it takes the password - except
// while protection is in the authorized paused state, where there is no active
// block to bypass. Mirrors disable-extension.
func unblockDomainCmd(cfg policy.Config, cfgPath, name, password string) {
	if strings.TrimSpace(name) == "" {
		fmt.Fprintln(os.Stderr, "error: domain required, e.g. `guard unblock-domain reddit.com`")
		os.Exit(2)
	}
	if !scm.IsDisabled() {
		requirePassword(password)
	}
	host, ok := cfg.SetDomainEnabled(name, false)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: %q is not in the block list\n", host)
		os.Exit(1)
	}
	writeConfig(cfg, cfgPath)
	must(enforce.Default().Apply(activeNow(cfg)))
	fmt.Printf("unblocked: %s is no longer filtered\n", host)
}

// governingBlocks names the blocks that put a domain on a schedule, so a user who
// blocks something and then sees it reachable understands why.
func governingBlocks(cfg policy.Config, host string) string {
	var ids []string
	for _, b := range cfg.Blocks {
		if b.GovernsDomain(host) {
			ids = append(ids, b.ID)
		}
	}
	if len(ids) == 0 {
		return ""
	}
	return strings.Join(ids, ", ")
}
