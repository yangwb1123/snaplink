package serverassets

import (
	"io/fs"

	"github.com/snaplink/sso/interfaces/web"
)

// AdminSubFS returns a sub-filesystem rooted at the admin/ entry of the
// embedded web.AdminFS so http.FileServerFS sees index.html at the root
// (i.e., /admin/ → web/admin/index.html). The web package owns the embed
// directive to stay within the Go embed path-restriction rules (no ".." in
// pattern). The panic is intentional — the embed directive guarantees the
// directory exists at compile time; a failure here indicates a build
// configuration error, not a runtime condition.
func AdminSubFS() fs.FS {
	sub, err := fs.Sub(web.AdminFS, "admin")
	if err != nil {
		panic("admin console: sub-filesystem setup failed: " + err.Error())
	}
	return sub
}
