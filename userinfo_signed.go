package sso

import (
	"net/http"
)

// userinfoSignedAlgEdDSA is the only `userinfo_signed_response_alg`
// value this server can satisfy today — matches the access-token /
// id-token signing algorithm.
const userinfoSignedAlgEdDSA = "EdDSA"

// maybeSignUserInfo returns true when it has handled the response
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
func (s *Server) maybeSignUserInfo(ctx HandlerContext, clientID string, body map[string]any) bool {
	if s.idTokenIssuer == nil || s.clientStore == nil || clientID == "" {
		return false
	}
	signer, ok := s.idTokenIssuer.(UserinfoSigner)
	if !ok {
		return false
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil || client == nil || client.UserinfoSignedResponseAlg == "" {
		return false
	}
	if client.UserinfoSignedResponseAlg != userinfoSignedAlgEdDSA {
		// Unsupported alg — fall through to JSON. The RP picks
		// up the misconfiguration from a discovery comparison.
		return false
	}
	jwt, err := signer.SignUserInfo(ctx.Request().Context(), client.ID, body)
	if err != nil {
		s.logger.Error("userinfo sign failed", "error", err, "client", client.ID)
		return false
	}
	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", "application/jwt")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jwt))
	return true
}
