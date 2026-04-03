package ui

import (
	"embed"
	"errors"
	"io/fs"
	"sync"
)

// webUIEmbed is the embedded React build output.
// This embeds all files from the dist directory at compile time.
//
//go:embed all:dist
var webUIEmbed embed.FS

// Cached filesystem for static assets to avoid recomputing fs.Sub on every call.
var (
	staticFS     fs.FS
	staticFSOnce sync.Once
)

var errStaticFSNotInitialized = errors.New("static filesystem not initialized")

// StaticFS returns the embedded static filesystem for the web UI.
// The returned fs.FS is rooted at the "dist" directory.
// This function is safe for concurrent use and caches the result.
//
// Returns an error if the embedded filesystem was not properly initialized.
func StaticFS() (fs.FS, error) {
	var err error
	staticFSOnce.Do(func() {
		staticFS, err = fs.Sub(webUIEmbed, "dist")
		if err != nil {
			// Reset staticFS to nil on error so subsequent calls return the error
			staticFS = nil
		}
	})

	if staticFS == nil {
		return nil, errors.Join(errStaticFSNotInitialized, err)
	}

	return staticFS, nil
}

