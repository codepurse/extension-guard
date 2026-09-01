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
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()
	err := wails.Run(&options.App{
		Title: "Extension Guard",

		// Opens maximised. The window is a console with a navigation rail and a
		// content pane rather than one long column, so the room is spent on
		// putting a page's worth of state side by side instead of behind a
		// scrollbar. Width and Height are what an un-maximised window restores
		// to; the minimum is the point below which the layout folds the rail
		// down to icons, and stopping there keeps it from being dragged into a
		// size nothing fits in.
		WindowStartState: options.Maximised,
		Width:            1360,
		Height:           860,
		MinWidth:         940,
		MinHeight:        620,

		// Matches --bg in the frontend, so a cold start does not flash a
		// different dark grey before the first paint.
		BackgroundColour: &options.RGBA{R: 11, G: 13, B: 18, A: 255},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.startup,
		Bind:             []interface{}{app},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
