package oidc

import (
	"net/http"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/spi"
)

// UserinfoSignedAlgEdDSA is the only `userinfo_signed_response_alg`
// value this server can satisfy today — matches the access-token /
// id-token signing algorithm. Other alg values fall through to JSON.
const UserinfoSignedAlgEdDSA = "EdDSA"

// UserinfoSigningDeps is what MaybeSignUserInfo needs. *sso.Server
// satisfies it via the accessor methods.
type UserinfoSigningDeps interface {
	IDTokenIssuer() IDTokenIssuer
	ClientStoreAccessor() core.ClientStore
	SrvLogger() spi.Logger
}

// MaybeSignUserInfo returns true when it has handled the response
// (signed JWT delivered to ctx) — callers MUST bail. False means
// the caller should fall through to the JSON response path.
//
// The signed-JWT path fires only when:
//   - clientID resolves to a registered client AND
//   - that client's UserinfoSignedResponseAlg is set AND
//   - the wired IDTokenIssuer implements UserinfoSigner
//
// Unsupported alg values (anything besides EdDSA) fall through to
// JSON — the spec says the AS MUST honor the request OR return JSON
// when it can't; we choose the latter to keep RPs working.
func MaybeSignUserInfo(d UserinfoSigningDeps, ctx core.HandlerContext, clientID string, body map[string]any) bool {
	idTokenIssuer := d.IDTokenIssuer()
	clientStore := d.ClientStoreAccessor()
	if idTokenIssuer == nil || clientStore == nil || clientID == "" {
		return false
	}
	signer, ok := idTokenIssuer.(UserinfoSigner)
	if !ok {
		return false
	}
	client, err := clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil || client == nil || client.UserinfoSignedResponseAlg == "" {
		return false
	}
	if client.UserinfoSignedResponseAlg != UserinfoSignedAlgEdDSA {
		// Unsupported alg — fall through to JSON. The RP picks up
		// the misconfiguration from a discovery comparison.
		return false
	}
	jwt, err := signer.SignUserInfo(ctx.Request().Context(), client.ID, body)
	if err != nil {
		d.SrvLogger().Error("userinfo sign failed", "error", err, "client", client.ID)
		return false
	}
	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", "application/jwt")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jwt))
	return true
}
