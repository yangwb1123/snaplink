package main

import (
	"io/fs"

	"github.com/snaplink/sso/web"
)

// portalSubFS returns a sub-filesystem rooted at the portal/ entry of the
// embedded web.PortalFS so http.FileServerFS sees index.html at the root
// (/portal/ -> web/portal/index.html). The web package owns the embed
// directive to stay within the Go embed path-restriction rules. The panic is
// intentional — the embed directive guarantees the directory exists at compile
// time, so a failure indicates a build configuration error.
func portalSubFS() fs.FS {
	sub, err := fs.Sub(web.PortalFS, "portal")
	if err != nil {
		panic("self-service portal: sub-filesystem setup failed: " + err.Error())
	}
	return sub
}
