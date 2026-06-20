package oauthwire

import (
	"net/http"
	"strings"

	"github.com/snaplink/sso/shared/core"
)

// BearerToken extracts the credential value from an Authorization:
// Bearer <token> header per RFC 6750 §2.1. Returns "" when the
// header is missing or doesn't carry the expected scheme prefix —
// callers must distinguish "no credential" from "bad credential" by
// branching on the empty string before downstream validation.
func BearerToken(r *http.Request) string {
	h := r.Header.Get(core.HeaderAuthorization)
	if !strings.HasPrefix(h, core.BearerPrefix) {
		return ""
	}
	return strings.TrimPrefix(h, core.BearerPrefix)
}
