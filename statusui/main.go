// Command statusui is the Ward status window - the day-to-day
// console. It is a Wails app: a Go backend (app.go) bound to an HTML/CSS
// frontend (frontend/dist) rendered via WebView2. It only reads state and
// verifies the password; all enforcement lives in the guard service.
package main

import (
	"context"
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
	darkGround  = options.RGBA{R: 0x0F, G: 0x12, B: 0x11, A: 255} // --bg #0F1211
	lightGround = options.RGBA{R: 0xF4, G: 0xF1, B: 0xE9, A: 255} // --bg #F4F1E9
)

// The window's size, floor and ceiling. Named rather than written inline
// because the three have to hold a relationship - floor <= opening <= ceiling
// - and a typo in one of six numbers is the kind of thing that ships.
const (
	openWidth  = 1360
	openHeight = 860

	// The point below which every page has folded to a single column and the
	// page tabs to icons. Below it nothing fits.
	minWidth  = 940
	minHeight = 620

	// The ceiling. Past about 1600 the extra width lands in the gap between a
	// rule and its state rather than in anything worth reading, so growing
	// further only spreads the same page thinner. It also does the work of
	// disabling maximise: Wails clamps the maximised rect to this, so the
	// button grows the window to the ceiling instead of to the screen.
	maxWidth  = 1600
	maxHeight = 1100
)

func main() {
	app := NewApp()

	// Resolved once, here, so the frame and the first paint agree. The page
	// re-resolves it for itself a moment later from prefers-color-scheme, and
	// the two answers come from the same Windows setting.
	pref := loadTheme()
	// Light-first, matching themeDefault and the token block: the fallback
	// side of this branch is the one a machine with no stored preference and
	// no readable system setting lands on.
	ground := lightGround
	if resolveTheme(pref) == themeDark {
		ground = darkGround
	}
	frame := windows.SystemDefault
	switch pref {
	case themeLight:
		frame = windows.Light
	case themeDark:
		frame = windows.Dark
	}

	err := wails.Run(&options.App{
		Title: "Ward",

		// It no longer opens maximised, and it has a ceiling.
		//
		// Maximised was right for the console this used to be, where every card
		// was sized by its contents and more width meant more of each page on
		// screen. It is wrong for the window now. The Overview has one card
		// that takes the leftover height and three fixed-height blocks above
		// it, the lists are tables with a capped subject column, and past about
		// 1600 the extra width goes into the gap between a rule and its state
		// rather than into anything worth reading. On a large monitor the
		// result was a full-screen window carrying a page and a half of content.
		//
		// MaxWidth/MaxHeight are the ceiling for dragging. The maximise button
		// is gone separately, by taking WS_MAXIMIZEBOX off the window in
		// maxbutton_windows.go - Wails only greys it via DisableResize, which
		// would also nail the window to exactly Width x Height, and 860 does
		// not fit a 1366x768 laptop.
		//
		// The floor stays where it was - the point below which every page has
		// folded to a single column and the tabs to icons.
		Width:     openWidth,
		Height:    openHeight,
		MinWidth:  minWidth,
		MinHeight: minHeight,
		MaxWidth:  maxWidth,
		MaxHeight: maxHeight,

		// Matches --bg in the theme the window is about to open in, so a cold
		// start does not flash the other one before the first paint.
		BackgroundColour: &ground,
		Windows:          &windows.Options{Theme: frame},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.startup,
		// The maximise button comes off here rather than in the options above,
		// because Wails only offers it bundled with DisableResize. DomReady
		// rather than Startup: the window has to exist before its style can be
		// changed. See maxbutton_windows.go.
		OnDomReady: func(ctx context.Context) { disableMaximise() },
		Bind:       []interface{}{app},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
