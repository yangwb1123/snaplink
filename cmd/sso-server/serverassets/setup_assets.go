package serverassets

import (
	"io/fs"

	"github.com/snaplink/sso/interfaces/web"
)

// SetupSubFS returns a sub-filesystem rooted at the setup/ entry of the
// embedded web.SetupFS so http.FileServerFS sees files at their bare names
// (index.html, app.js, style.css) under /setup/. The web package owns the
// embed directive to stay within Go embed path-restriction rules (no ".." in
// pattern). The call to fs.Sub panics on error — the embed directive
// guarantees the directory exists at compile time, so failure indicates a
// build configuration error. Mirrors LoginSubFS.
func SetupSubFS() fs.FS {
	sub, err := fs.Sub(web.SetupFS, "setup")
	if err != nil {
		panic("setup assets: sub-filesystem setup failed: " + err.Error())
	}
	return sub
}
