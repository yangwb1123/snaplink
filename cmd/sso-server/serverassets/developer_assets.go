package serverassets

import (
	"io/fs"

	"github.com/snaplink/sso/interfaces/web"
)

// DeveloperSubFS returns a sub-filesystem rooted at the developer/ entry of
// the embedded web.DeveloperFS so http.FileServerFS sees index.html at the
// root (i.e., /developer/ → web/developer/index.html). Mirrors AdminSubFS/
// LoginSubFS/PortalSubFS's panic-on-setup-failure rationale — the embed
// directive guarantees the directory exists at compile time.
func DeveloperSubFS() fs.FS {
	sub, err := fs.Sub(web.DeveloperFS, "developer")
	if err != nil {
		panic("developer portal: sub-filesystem setup failed: " + err.Error())
	}
	return sub
}
