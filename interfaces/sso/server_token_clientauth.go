package sso

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/security"
)

// ClientAuthWorkloadIdentity marks a registered Client as requiring a cloud
// workload-identity token (AWS/GCP/Azure — see
// shared/security/securityverify's package doc for per-cloud status)
// instead of a client_secret or private_key_jwt. Not IANA-registered (no
// such token_endpoint_auth_method value exists yet); the plain, unprefixed
// name mirrors how ClientAuthTLS/ClientAuthSelfSignedTLS are also this
// server's own conventions rather than RFC 8414-published strings.
const ClientAuthWorkloadIdentity = "workload_identity"

// ClientAssertionTypeWorkloadIdentity marks an inbound client_assertion as a
// cloud-issued workload-identity token, verified against the CLOUD's own
// published JWKS (WithWorkloadIdentityProviders) instead of the client's
// registered JWKS — contrast ClientAssertionTypeJWTBearer, which verifies
// against Client.JWKS. Scoped under a snaplink: URN so it can never collide
// with a future IETF-registered client-assertion-type.
const ClientAssertionTypeWorkloadIdentity = "urn:snaplink:params:oauth:client-assertion-type:workload-identity"

// resolveAssertedClientID applies RFC 7521 §4.2 client-assertion-based
// authentication when the request carries a client_assertion, dispatching on
// client_assertion_type. Returns true (handled) when a response was ALREADY
// written; the caller MUST then stop.
//
//   - ClientAssertionTypeJWTBearer (RFC 7523 §2.2, private_key_jwt): the JWT
//     replaces client_secret as proof of identity, verified against
//     Client.JWKS. On success req.ClientID is OVERWRITTEN with the asserted
//     id (the JWT `sub` IS the client_id — see verifyJWTClientAssertion).
//   - ClientAssertionTypeWorkloadIdentity: a cloud-issued token, verified
//     against the cloud's OWN JWKS and mapped onto the identity the
//     ALREADY-known req.ClientID (form client_id) is configured to expect —
//     see verifyWorkloadIdentityClientAssertion. req.ClientID is NOT
//     rewritten (a cloud subject is not this server's client_id).
//   - anything else → invalid_request (an unsupported assertion type).
func (s *Server) resolveAssertedClientID(ctx HandlerContext, req *oauth.TokenRequest) bool {
	if req.ClientAssertion == "" && req.ClientAssertionType == "" {
		return false
	}
	switch req.ClientAssertionType {
	case ClientAssertionTypeJWTBearer:
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
			ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidClient))
			return true
		}
		req.ClientID = assertedID
		return false
	case ClientAssertionTypeWorkloadIdentity:
		if err := s.verifyWorkloadIdentityClientAssertion(ctx, req); err != nil {
			ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidClient))
			return true
		}
		return false
	default:
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return true
	}
}

// verifyWorkloadIdentityClientAssertion authenticates a client configured
// for cloud workload-identity auth (ClientAuthWorkloadIdentity): the inbound
// client_assertion is a cloud-issued token, verified against the CLOUD's OWN
// published JWKS — NOT the client's registered JWKS (contrast
// verifyJWTClientAssertion). Unlike JWT-bearer, the cloud token's verified
// identity is NOT this server's client_id, so req.ClientID (the form
// client_id, or HTTP Basic username — see authenticateTokenClient) drives
// the lookup and is never overwritten.
//
// Gate order, each failing to the SAME opaque error (oracle-leak hardening,
// AGENTS.md §3 "private_key_jwt failure -> invalid_client"):
//
//  1. req.ClientID resolves to a registered client configured with
//     TokenEndpointAuthMethod == ClientAuthWorkloadIdentity and both
//     required Client.Attributes present.
//  2. the named provider validates the token: signature against the cloud's
//     JWKS, temporal window, issuer, and aud == this server's issuer
//     (mirrors the private_key_jwt aud-binding requirement — WHICH relying
//     party the token was minted for).
//  3. the mapped identity's Subject equals the client's registered
//     AttrWorkloadIdentitySubject EXACTLY — the security crux: it is what
//     stops ANY OTHER workload the cloud provider will vouch for from
//     impersonating a DIFFERENT registered client.
func (s *Server) verifyWorkloadIdentityClientAssertion(ctx HandlerContext, req *oauth.TokenRequest) error {
	if req.ClientID == "" {
		return errors.New("workload_identity: client_id required")
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil || client == nil {
		return errors.New("workload_identity: client not found")
	}
	if client.TokenEndpointAuthMethod != ClientAuthWorkloadIdentity {
		return errors.New("workload_identity: client not configured for workload identity")
	}
	providerName := client.Attributes[security.AttrWorkloadIdentityProvider]
	expectedSubject := client.Attributes[security.AttrWorkloadIdentitySubject]
	if providerName == "" || expectedSubject == "" {
		return errors.New("workload_identity: client missing provider/subject attributes")
	}
	provider, ok := s.workloadIdentityProviders[providerName]
	if !ok {
		return errors.New("workload_identity: provider not configured")
	}
	identity, err := provider.Validate(ctx.Request().Context(), req.ClientAssertion, s.resolveIssuer(ctx))
	if err != nil {
		return err
	}
	if identity.Subject != expectedSubject {
		return errors.New("workload_identity: subject mismatch")
	}
	return nil
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
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidClient))
		return nil, basicAuthUsed, true
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ctx, ErrTenantMismatch))
		return nil, basicAuthUsed, true
	}

	if !s.verifyTokenClientAuth(ctx, client, req) {
		return nil, basicAuthUsed, true
	}

	// RFC 8707 §2: each requested `resource` MUST be allowlisted on
	// the client. Empty allowlist disables enforcement (legacy compat).
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidTarget))
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
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidClient))
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
			ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidClient))
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
	reqCtx := ctx.Request().Context()
	switch authMethod {
	case ClientAuthTLS:
		return s.verifyTLSClientAuthCert(reqCtx, client, cert)
	case ClientAuthSelfSignedTLS:
		return s.verifySelfSignedTLSCert(reqCtx, client, cert)
	}
	return false
}

// verifyTLSClientAuthCert verifies cert's DN/SAN binding against client's
// registered tls_client_auth attributes and, if bound, checks revocation.
// Split out of authenticateMTLSClient to stay within the function-length
// budget.
func (s *Server) verifyTLSClientAuthCert(ctx context.Context, client *Client, cert *x509.Certificate) bool {
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
	if s.mtlsCertRevoked(ctx, client, cert) {
		s.logger.Error("tls_client_auth failed: certificate revoked", "client_id", client.ID)
		return false
	}
	return true
}

// verifySelfSignedTLSCert verifies cert's public key matches one of
// client's registered JWKs and, if matched, checks revocation. Split out of
// authenticateMTLSClient to stay within the function-length budget.
func (s *Server) verifySelfSignedTLSCert(ctx context.Context, client *Client, cert *x509.Certificate) bool {
	if len(client.JWKS) == 0 {
		s.logger.Error("self_signed_tls failed: client has no JWKS",
			"client_id", client.ID)
		return false
	}
	// Check if any JWK matches the cert's public key.
	for _, jwk := range client.JWKS {
		match, err := security.CertPublicKeyMatchesJWK(cert,
			jwk.Kty, jwk.Crv, jwk.X, jwk.Y, jwk.N, jwk.E)
		if err != nil || !match {
			continue
		}
		if s.mtlsCertRevoked(ctx, client, cert) {
			s.logger.Error("self_signed_tls failed: certificate revoked", "client_id", client.ID)
			return false
		}
		return true
	}
	s.logger.Error("self_signed_tls failed: no matching JWK",
		"client_id", client.ID)
	return false
}

// mtlsCertRevoked reports whether cert is revoked per the configured
// [spi.CertRevocationChecker] (WithMTLSRevocationChecker), fail-open on
// checker error — matching RiskScorer's availability convention (see
// shared/spi/risk.go). No checker wired ⇒ never revoked (historical,
// chain+DN/SAN/JWK-only behavior).
func (s *Server) mtlsCertRevoked(ctx context.Context, client *Client, cert *x509.Certificate) bool {
	if s.mtlsRevocationChecker == nil {
		return false
	}
	revoked, err := s.mtlsRevocationChecker.IsRevoked(ctx, cert)
	if err != nil {
		s.logger.Error("mtls revocation check failed, allowing (fail-open)",
			"client_id", client.ID, "error", err.Error())
		return false
	}
	return revoked
}

// --- Token validation -------------------------------------------------
//
// Lives here (not a dedicated file) because interfaces/sso is at its frozen
// file-count ceiling (directory_fanout_test.go). Thematically adjacent to
// the client-auth concerns above (both are token-endpoint-side gates).

func (s *Server) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	claims, _, err := s.validateAnyToken(ctx, token)
	if err == nil && claims != nil && claims.SID != "" {
		trackSessionActivity(ctx, s.sessionMgr, claims.SID)
	}
	return claims, err
}

// validateTokenPreChecks runs the two Server-level defense-in-depth gates
// BEFORE any issuer sees the token: a byte-length ceiling (WithMaxTokenBytes)
// and the JWS `alg` allowlist (WithSupportedSigningAlgs). Split out of
// validateAnyToken to keep it within the function-length budget; both
// checks are unbounded/no-op (nil error) unless the operator configured
// them, so this is byte-identical to today when neither option is wired.
func (s *Server) validateTokenPreChecks(token string) error {
	// Byte-length gate: a caller handing the server a deliberately huge
	// "token" string shouldn't get to spend CPU on base64 + JSON parsing
	// before the eventual (inevitable) verification failure. The generic
	// error below is intentional: every caller of validateAnyToken already
	// collapses ANY non-nil error to the standard oracle-safe
	// invalid_token/inactive response, never inspecting content.
	if s.maxTokenBytes > 0 && len(token) > s.maxTokenBytes {
		return fmt.Errorf("token exceeds max_token_bytes (%d)", s.maxTokenBytes)
	}
	// alg allowlist gate: reject any compact-JWS bearer whose header `alg`
	// isn't allowed BEFORE any issuer runs — so the verification algorithm
	// is fixed by the operator, never picked by the RP. Opaque (non-JWT)
	// tokens carry no JOSE header and pass through untouched to the
	// session/opaque issuers.
	if len(s.supportedSigningAlgs) > 0 {
		if alg, ok := jwsHeaderAlg(token); ok && !algAllowed(alg, s.supportedSigningAlgs) {
			return fmt.Errorf("token alg %q not in supported_signing_algs", alg)
		}
	}
	return nil
}

// validateAnyToken tries each registered issuer until one accepts the token.
// Returned issuerName lets callers correlate revocations or audit logs.
func (s *Server) validateAnyToken(ctx context.Context, token string) (*TokenClaims, string, error) {
	if err := s.validateTokenPreChecks(token); err != nil {
		return nil, "", err
	}
	var lastErr error
	for name, ti := range s.tokenIssuers {
		// Skip issuers that explicitly opt out of this token's shape.
		// Saves an expensive base64 + signature attempt when a session
		// token reaches the JWT issuer or vice versa. Issuers without
		// a TokenFormatHinter are always tried (legacy behavior).
		if h, ok := ti.(TokenFormatHinter); ok && !h.AcceptsTokenFormat(token) {
			continue
		}
		claims, err := ti.Validate(ctx, token)
		if err == nil {
			// Post-validation tenant suspension gate.
			// No-op when WithTenantSuspensionCheck wasn't passed; otherwise
			// hard-fails tokens whose owning client belongs to a now-
			// suspended tenant so an admin's Suspended flip cuts off
			// already-issued bearers, not just future issuance.
			if tsErr := s.checkTenantNotSuspended(ctx, claims); tsErr != nil {
				return nil, "", tsErr
			}
			// NOTE(region): this bare-context validate has no serving region
			// (stashed on HandlerContext, out of scope here) — but the read
			// gate isn't missing: residencyDeniedForAccess
			// (server_tenant_residency.go) is a SEPARATE post-validation gate
			// each HandlerContext-having caller invokes directly, covering
			// /userinfo, mesh ext_authz, and GET /me[/data-export]
			// (ResidencyGateAccess). /token/introspect is deliberately
			// excluded (see WithTenantResidencyCheck's doc). The admin plane
			// and token-exchange's inbound subject_token read do NOT call
			// this gate yet — a product/security decision for a follow-up,
			// not a mechanical fix (admin already has its own admin:read/
			// admin:write boundary). The login (write/mint) gate in
			// handler.go remains the primary residency control regardless.
			return claims, name, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no token issuers registered")
	}
	return nil, "", lastErr
}

// revokeAcrossIssuers asks every registered issuer to revoke the token.
// Revoke is expected to be tolerant of unknown tokens (the issuer that
// doesn't own the token returns ErrNoSuchToken or similar — that's a
// no-op, not a failure). Returns:
//
//   - revoked: names of issuers whose Revoke returned nil.
//   - failed: names of issuers whose Revoke returned a non-nil, non-
//     "unknown token" error — these are the ones where the bearer
//     may still work and the caller should audit
//     `partial_revoke_failure`.
//
// The split lets the caller distinguish "no issuer owned this token"
// (revoked empty, failed empty — benign) from "an issuer that DOES
// own this token failed to revoke" (revoked empty, failed non-empty
// — bug or infra issue that violates the logout-everywhere promise).
func (s *Server) revokeAcrossIssuers(ctx context.Context, token string) (revoked, failed []string) {
	for name, ti := range s.tokenIssuers {
		// Honor the same shape-skip the validate path uses. An
		// issuer whose TokenFormatHinter rejects the inbound token
		// can't possibly own it, so asking it to Revoke would either
		// (a) return a not-found error we ignore anyway, or (b)
		// return an infra error we'd misclassify as a partial
		// revoke failure. Skip cleanly.
		if h, ok := ti.(TokenFormatHinter); ok && !h.AcceptsTokenFormat(token) {
			continue
		}
		switch err := ti.Revoke(ctx, token); {
		case err == nil:
			revoked = append(revoked, name)
		case isUnknownTokenErr(err):
			// Issuer didn't own this token — expected when callers
			// sweep across N issuers. Not a failure.
		default:
			failed = append(failed, name)
		}
	}
	// Best-effort: evict any cached /token/introspect result for this exact
	// token immediately rather than waiting out the cache TTL (AGENTS.md §3
	// Oracle-Leak Hardening — a revoked token must not keep reporting
	// active:true to a caller who introspects it right after this call).
	// This unexported method is the SINGLE choke point every revocation path
	// in this codebase funnels through: the exported RevokeAcrossIssuers
	// wraps it (used by /token/revoke, /logout, /token/revoke-all's
	// presented bearer, and the admin gRPC revoke), and the cross-replica
	// ApplyTokenRevocation adoption arm calls this method directly — so
	// instrumenting here covers all of them from one place. Fires
	// regardless of whether any issuer actually owned the token, matching
	// RFC 7009 §2.2's anti-enumeration contract (a caller can't tell
	// found-and-revoked from unknown, so this can't leak that either).
	// No-op when caching is unwired or the backend doesn't support
	// point-eviction — see oauth.InvalidateIntrospectionCache.
	oauth.InvalidateIntrospectionCache(s.introspectionCache, token)
	return revoked, failed
}

// isUnknownTokenErr heuristically classifies an issuer's Revoke
// error. The error surface across issuers is loose (each impl
// returns its own sentinel — Ed25519 issuer returns nil for
// stateless tokens; SessionTokenIssuer returns "session_issuer:
// token not found"). Treat the standard "not found" / "unknown"
// shapes as no-op; everything else is infra failure worth auditing.
// When an issuer adopts a typed sentinel (e.g. ErrUnknownToken), add
// it here.

func isUnknownTokenErr(err error) bool           { return handler.IsUnknownTokenErr(err) }
func jwsHeaderAlg(token string) (string, bool)   { return handler.JWSHeaderAlg(token) }
func algAllowed(alg string, allow []string) bool { return handler.AlgAllowed(alg, allow) }
