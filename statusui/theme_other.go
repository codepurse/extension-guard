//go:build !windows

package main

// systemPrefersLight has no portable answer off Windows, so "follow the
// system" resolves to the theme this window has always opened in. The webview
// still reads the real prefers-color-scheme once it is up, so a Linux desktop
// in light mode gets a light page - only the frame colour painted before the
// first frame is a guess, and it is a guess in the direction of the default.
func systemPrefersLight() bool { return false }
