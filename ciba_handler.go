package sso

import (
	"context"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/oauth"
)

// handleBackchannelAuth delegates to oauth.HandleBackchannelAuth —
// see that file for the OIDC CIBA Core 1.0 poll-mode flow.
func (s *Server) handleBackchannelAuth(ctx HandlerContext) { oauth.HandleBackchannelAuth(s, ctx) }

// ResolveCIBAHint maps a CIBA request's hints to a known user's subject
// id. Poll mode: at least one hint must resolve. login_hint is matched
// against UserProvider.GetByID (the canonical identifier); id_token_hint
// is validated and its sub trusted; login_hint_token is treated as an
// opaque GetByID lookup. Returns ("", nil) when nothing resolves — the
// handler collapses that to unknown_user_id (anti-enumeration). The
// provider name is recorded for the AMR claim ("ciba" — out-of-band
// confirmation).
func (s *Server) ResolveCIBAHint(ctx context.Context, loginHint, idTokenHint, loginHintToken string) (string, string, error) {
	// id_token_hint: validate the token and trust its subject. The
	// validator rejects expired / wrong-alg / bad-signature tokens.
	if idTokenHint != "" {
		if claims, err := s.ValidateToken(ctx, idTokenHint); err == nil && claims != nil && claims.Subject != "" {
			return claims.Subject, CIBAAMR, nil
		}
	}
	if s.userProvider == nil {
		return "", "", nil
	}
	for _, hint := range []string{loginHint, loginHintToken} {
		if hint == "" {
			continue
		}
		if u, err := s.userProvider.GetByID(ctx, hint); err == nil && u != nil {
			return u.ID, CIBAAMR, nil
		}
	}
	return "", "", nil
}

// CIBAAMR is the AMR / provider value recorded for a token minted via
// the CIBA grant — the user confirmed out of band on a separate
// authentication device.
const CIBAAMR = "ciba"

// DeliverCIBAChallenge pushes the auth_req_id out of band via the wired
// CIBA transport. binding_message is forwarded under the metadata key
// so the device app can render it for the user to correlate.
func (s *Server) DeliverCIBAChallenge(ctx context.Context, authReqID, subjectID, bindingMessage string) error {
	if s.cibaTransport == nil {
		return oauth.ErrCIBARequestInvalid
	}
	var meta map[string]string
	if bindingMessage != "" {
		meta = map[string]string{"binding_message": bindingMessage}
	}
	return s.cibaTransport.Send(ctx, authReqID, subjectID, meta)
}

// RecordCIBAAuthRequest emits the ciba_auth_request audit event.
func (s *Server) RecordCIBAAuthRequest(ctx HandlerContext, clientID, subjectID, authReqID string) {
	audit.RecordCIBAAuthRequest(s.auditor, ctx, clientID, subjectID, authReqID)
}

// recordCIBADecision emits a ciba_approved / ciba_denied audit event.
func (s *Server) recordCIBADecision(ctx HandlerContext, clientID, subjectID string, approved bool) {
	audit.RecordCIBADecision(s.auditor, ctx, clientID, subjectID, approved)
}

// handleRevoke implements RFC 7009 token revocation. Per-token
// revocation that's complementary to /logout (which is session-scoped).
//
// Auth: same client credentials as /token/introspect. Per §2 any
// registered active client may revoke — but the server MUST NOT
// distinguish revocation of an unknown token from a successful
// revocation (§2.2), so the wire response is always 200 OK with an
// empty body when the credentials are valid, regardless of whether
// the token existed.
//
// token_type_hint is honored as an optimization (try the named tier
// first) but the server still attempts the other tier on miss, so a
// wrong hint doesn't leave the token alive.
