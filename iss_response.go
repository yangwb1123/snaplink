package sso

// RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification.
//
// Defense against mix-up attacks: when a client is configured with
// multiple authorization servers, an attacker can attempt to trick the
// client into accepting an authorization response from one AS as if it
// came from another. Including the AS issuer identifier in every
// authorization response lets the client verify "this code/token came
// from the AS I expected" before redeeming the code at the token
// endpoint.
//
// RFC 9207 §2 is written for redirect-based responses (`?iss=...`
// query param on the redirect to the RP). This server's /auth/login is
// a BFF-shaped JSON endpoint rather than a 302-redirect endpoint; the
// adaptation is to include `iss` in the JSON response body alongside
// `code` / `state` / `error`. A client that builds the redirect URI
// on the SPA side can propagate the value into `iss=...` as the spec
// intends.

// resolveIssuer returns the issuer identifier this server stamps in
// authorization responses. Matches the value advertised in the OIDC
// discovery document: operator-configured `WithIssuer` value when set
// and not the default sentinel; otherwise the request's base URL.
//
// Critical invariant: the value returned here MUST equal
// `oidcConfiguration.Issuer` for the same request — RFC 9207 §2
// requires the `iss` parameter to be the same identifier the AS
// publishes via discovery, so a client comparing them detects mix-up.
func (s *Server) resolveIssuer(ctx HandlerContext) string {
	if s.issuer != "" && s.issuer != DefaultIssuer {
		return s.issuer
	}
	return requestBaseURL(ctx.Request())
}

// authzErrorBody returns the standard error envelope for an
// authorization endpoint response with `iss` stamped per RFC 9207 §2.
// Use this in handleLogin (and any future authorization endpoint) —
// NOT in token / userinfo / callback handlers, which are not
// authorization responses.
func (s *Server) authzErrorBody(ctx HandlerContext, code string) map[string]string {
	return map[string]string{
		KeyError: code,
		KeyIss:   s.resolveIssuer(ctx),
	}
}

// authzErrorBodyDesc is authzErrorBody plus an error_description.
func (s *Server) authzErrorBodyDesc(ctx HandlerContext, code, desc string) map[string]string {
	return map[string]string{
		KeyError:            code,
		KeyErrorDescription: desc,
		KeyIss:              s.resolveIssuer(ctx),
	}
}
