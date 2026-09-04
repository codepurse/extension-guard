//go:build !windows

package main

// systemPrefersLight has no portable answer off Windows, so "follow the
// system" resolves to the theme this window opens in by default. The webview
// still reads the real prefers-color-scheme once it is up, so a Linux desktop
// in dark mode gets a dark page - only the frame colour painted before the
// first frame is a guess, and it is a guess in the direction of the default.
//
// It returns true now because that default is light. The rule is the one it
// always was; the answer moved with themeDefault.
func systemPrefersLight() bool { return true }
