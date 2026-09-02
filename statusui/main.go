// Command statusui is the Extension Guard status window - the day-to-day
// console. It is a Wails app: a Go backend (app.go) bound to an HTML/CSS
// frontend (frontend/dist) rendered via WebView2. It only reads state and
// verifies the password; all enforcement lives in the guard service.
package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

// The two grounds, matching --bg in each theme's token block. The window
// paints one of these before the webview has rendered anything, so getting it
// wrong is a flash of the other theme for the length of a cold start - which
// is the whole reason the preference is stored where Go can read it rather
// than only in the page's localStorage.
var (
	darkGround  = options.RGBA{R: 14, G: 16, B: 20, A: 255}
	lightGround = options.RGBA{R: 236, G: 238, B: 243, A: 255}
)

func main() {
	app := NewApp()

	// Resolved once, here, so the frame and the first paint agree. The page
	// re-resolves it for itself a moment later from prefers-color-scheme, and
	// the two answers come from the same Windows setting.
	pref := loadTheme()
	ground := darkGround
	if resolveTheme(pref) == themeLight {
		ground = lightGround
	}
	frame := windows.SystemDefault
	switch pref {
	case themeLight:
		frame = windows.Light
	case themeDark:
		frame = windows.Dark
	}

	err := wails.Run(&options.App{
		Title: "Extension Guard",

		// Opens maximised. The window is a console - a navigation rail, a
		// toolbar, a workspace of docked panes and a status bar - and nothing
		// in it scrolls except the inside of a pane, so the room the window is
		// given is the room the pages get. Width and Height are what an
		// un-maximised window restores to; the minimum is the point below which
		// the layout has folded every page to a single column and the rail down
		// to icons, and stopping there keeps it from being dragged into a size
		// nothing fits in.
		WindowStartState: options.Maximised,
		Width:            1360,
		Height:           860,
		MinWidth:         940,
		MinHeight:        620,

		// Matches --bg in the theme the window is about to open in, so a cold
		// start does not flash the other one before the first paint.
		BackgroundColour: &ground,
		Windows:          &windows.Options{Theme: frame},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.startup,
		Bind:             []interface{}{app},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
