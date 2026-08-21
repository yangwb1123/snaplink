package oauthwire

import (
	"net/http"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
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

// ResourceToken extracts an access token sent with either the RFC 6750
// Bearer scheme or the RFC 9449 DPoP scheme. Token endpoints and management
// endpoints must continue using BearerToken, while protected resources need
// both schemes because a DPoP-bound token is sent as "DPoP <token>".
func ResourceToken(r *http.Request) string {
	if token := BearerToken(r); token != "" {
		return token
	}
	h := r.Header.Get(core.HeaderAuthorization)
	if !strings.HasPrefix(h, core.DPoPPrefix) {
		return ""
	}
	return strings.TrimPrefix(h, core.DPoPPrefix)
}
