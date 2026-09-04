//go:build !windows

package main

// disableMaximise is a no-op off Windows. The caption buttons are the window
// manager's there, not the app's, and a Linux build of this window is a
// development convenience rather than something anybody ships.
func disableMaximise() {}
