package serverassets

import (
	"io/fs"

	"github.com/snaplink/sso/interfaces/web"
)

// LoginSubFS returns a sub-filesystem rooted at the login/ entry of the
// embedded web.LoginFS so http.FileServerFS sees files at their bare names
// (index.html, app.js, style.css) under /login/. The web package owns the
// embed directive to stay within Go embed path-restriction rules (no ".." in
// pattern). The call to fs.Sub panics on error — the embed directive
// guarantees the directory exists at compile time, so failure indicates a
// build configuration error.
func LoginSubFS() fs.FS {
	sub, err := fs.Sub(web.LoginFS, "login")
	if err != nil {
		panic("login assets: sub-filesystem setup failed: " + err.Error())
	}
	return sub
}
