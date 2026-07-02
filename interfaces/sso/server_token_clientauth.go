package sso

import (
	"net/http"

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/security"
)

// resolveAssertedClientID applies RFC 7521 §4.2 + RFC 7523 §2.2 JWT-bearer
// client authentication when the request carries a client_assertion. The JWT
// replaces client_secret as proof of identity: it MUST be signed by a key in
// Client.JWKS; iss / sub MUST equal the client_id; aud MUST include the AS
// issuer or token endpoint URL; exp MUST be in the future. Replay defense (jti
// tracking) reuses the security.JTIReplayStore wiring JAR already opts into. On
// success req.ClientID is overwritten with the asserted id. Returns true
// (handled) when a response was ALREADY written; the caller MUST then stop.
func (s *Server) resolveAssertedClientID(ctx HandlerContext, req *oauth.TokenRequest) bool {
	if req.ClientAssertion == "" && req.ClientAssertionType == "" {
		return false
	}
	if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return true
	}
	assertedID, err := verifyJWTClientAssertion(
		ctx.Request().Context(),
		req.ClientAssertion,
		req.ClientID,
		s.clientStore,
		s.resolveIssuer(ctx),
		s.jtiReplayStore,
		s.jtiReplayFailClosed,
	)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return true
	}
	req.ClientID = assertedID
	return false
}

// authenticateTokenClient runs the client-identification + authentication
// gate ladder (assertion -> lookup -> tenant -> mTLS/secret -> resource) and
// returns the resolved client plus whether HTTP Basic creds were used. When
// handled==true a response has ALREADY been written and the caller MUST return
// immediately. Gate order is load-bearing: tenant precedes auth precedes
// resource, and every failure collapses to its oracle-safe wire code.
//
// mTLS client auth (RFC 8705 §2): clients registered with
// token_endpoint_auth_method="tls_client_auth" present their certificate
// instead of a client_secret. The cert must match the registered
// TLSClientAuthSubjectDN, SAN DNS, SAN email, or SAN URI constraints.
// Clients with "self_signed_tls" must present a self-signed cert whose
// public key matches a registered JWK.
func (s *Server) authenticateTokenClient(ctx HandlerContext, req *oauth.TokenRequest) (client *Client, basicAuthUsed bool, handled bool) {
	// HTTP Basic auth takes precedence over body fields per RFC 6749 §2.3.1.
	if id, secret, ok := basicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
		basicAuthUsed = true
	}

	if s.resolveAssertedClientID(ctx, req) {
		return nil, basicAuthUsed, true
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return nil, basicAuthUsed, true
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ErrTenantMismatch))
		return nil, basicAuthUsed, true
	}

	if !s.verifyTokenClientAuth(ctx, client, req) {
		return nil, basicAuthUsed, true
	}

	// RFC 8707 §2: each requested `resource` MUST be allowlisted on
	// the client. Empty allowlist disables enforcement (legacy compat).
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return nil, basicAuthUsed, true
	}

	return client, basicAuthUsed, false
}

// verifyTokenClientAuth applies the mTLS / client_secret leg of the gate
// ladder, exactly as it ran inline in authenticateTokenClient. Returns false
// when authentication failed — the oracle-safe response has ALREADY been
// written and the caller MUST stop.
func (s *Server) verifyTokenClientAuth(ctx HandlerContext, client *Client, req *oauth.TokenRequest) bool {
	// mTLS client authentication (RFC 8705 §2): when the client is
	// registered with tls_client_auth or self_signed_tls, verify the
	// presented client certificate instead of the client_secret.
	usingMTLS := s.authenticateMTLSClient(ctx, client)
	if usingMTLS {
		// mTLS auth handled the authentication; skip secret validation.
		// However, if mTLS auth failed, authenticateMTLSClient already
		// wrote the response and returned true (handled), so we'd have
		// returned above. If we reach here, mTLS auth succeeded.
	} else if client.TokenEndpointAuthMethod == ClientAuthTLS ||
		client.TokenEndpointAuthMethod == ClientAuthSelfSignedTLS {
		// Client requires mTLS but extraction/verification failed.
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return false
	}

	// Skip the client_secret check when the caller authenticated
	// via JWT assertion OR mTLS — both stand in for the secret.
	if req.ClientAssertion == "" && !usingMTLS &&
		client.TokenEndpointAuthMethod != ClientAuthTLS &&
		client.TokenEndpointAuthMethod != ClientAuthSelfSignedTLS {
		if err := s.clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
			// RFC 6749 §5.2: all client-authentication failures return
			// invalid_client. Collapsing wrong-secret into the same code as
			// unknown-client (above) is also oracle-safe — a distinct
			// invalid_client_secret would let an attacker enumerate valid
			// client_ids by the error code alone.
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
			return false
		}
	}
	return true
}

// authenticateMTLSClient verifies the presented client certificate when the
// client is registered with token_endpoint_auth_method="tls_client_auth" or
// "self_signed_tls". Returns true when mTLS authentication was SUCCESSFULLY
// verified (the calling gate skips secret validation). Returns false when no
// mTLS auth was required or attempted. When verification fails, it writes the
// response and calls handledCallback(false) before returning true so the caller
// treats the request as handled.
func (s *Server) authenticateMTLSClient(ctx HandlerContext, client *Client) bool {
	authMethod := client.TokenEndpointAuthMethod
	if authMethod != ClientAuthTLS && authMethod != ClientAuthSelfSignedTLS {
		return false
	}
	if s.clientCertExtractor == nil {
		return false
	}
	cert, ok := s.clientCertExtractor.ExtractClientCert(ctx.Request())
	if !ok || cert == nil {
		return false
	}
	switch authMethod {
	case ClientAuthTLS:
		if err := security.VerifyTLSClientAuth(cert,
			client.TLSClientAuthSubjectDN,
			client.TLSClientAuthSANDNS,
			client.TLSClientAuthSANEmail,
			client.TLSClientAuthSANURI,
		); err != nil {
			s.logger.Error("tls_client_auth failed",
				"client_id", client.ID,
				"error", err.Error(),
				"subject", cert.Subject.String())
			return false
		}
		return true
	case ClientAuthSelfSignedTLS:
		if len(client.JWKS) == 0 {
			s.logger.Error("self_signed_tls failed: client has no JWKS",
				"client_id", client.ID)
			return false
		}
		// Check if any JWK matches the cert's public key.
		for _, jwk := range client.JWKS {
			match, err := security.CertPublicKeyMatchesJWK(cert,
				jwk.Kty, jwk.Crv, jwk.X, jwk.Y, jwk.N, jwk.E)
			if err != nil {
				continue
			}
			if match {
				return true
			}
		}
		s.logger.Error("self_signed_tls failed: no matching JWK",
			"client_id", client.ID)
		return false
	}
	return false
}
