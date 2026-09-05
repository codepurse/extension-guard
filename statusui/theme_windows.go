//go:build windows

package main

import "golang.org/x/sys/windows/registry"

// systemPrefersLight reads the Windows personalisation setting the rest of the
// desktop follows. AppsUseLightTheme is what Settings > Personalisation >
// Colours writes when "Choose your default app mode" changes, and it is the
// same value the webview's prefers-color-scheme resolves from - so the frame
// the backend paints and the page the frontend paints agree.
//
// Anything unreadable is dark, which is what this window has always been.
func systemPrefersLight() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	v, _, err := key.GetIntegerValue("AppsUseLightTheme")
	if err != nil {
		return false
	}
	return v == 1
}
