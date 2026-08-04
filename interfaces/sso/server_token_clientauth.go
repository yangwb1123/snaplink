package sso

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/yangwb1123/snaplink/internal/handler"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/security"
)

// ClientAuthWorkloadIdentity requires a verified cloud workload token instead
// of a client secret or private_key_jwt assertion.
const ClientAuthWorkloadIdentity = "workload_identity"

// ClientAssertionTypeWorkloadIdentity selects cloud-provider assertion
// verification rather than verification against Client.JWKS.
const ClientAssertionTypeWorkloadIdentity = "urn:snaplink:params:oauth:client-assertion-type:workload-identity"

type tokenClientAuthKind uint8

const (
	tokenAuthInvalid tokenClientAuthKind = iota
	tokenAuthUnsupportedAssertion
	tokenAuthNone
	tokenAuthBasic
	tokenAuthPost
	tokenAuthPrivateKeyJWT
	tokenAuthWorkloadIdentity
)

// tokenClientAuthEvidence records which credential transport was present,
// without retaining a secret or assertion in a loggable value.
type tokenClientAuthEvidence struct {
	basic         bool
	bodySecret    bool
	assertion     bool
	assertionType string
}

func (e tokenClientAuthEvidence) kind() tokenClientAuthKind {
	count := 0
	if e.basic {
		count++
	}
	if e.bodySecret {
		count++
	}
	if e.assertion {
		count++
	}
	if count > 1 {
		return tokenAuthInvalid
	}
	if e.basic {
		return tokenAuthBasic
	}
	if e.bodySecret {
		return tokenAuthPost
	}
	if !e.assertion {
		return tokenAuthNone
	}
	switch e.assertionType {
	case ClientAssertionTypeJWTBearer:
		return tokenAuthPrivateKeyJWT
	case ClientAssertionTypeWorkloadIdentity:
		return tokenAuthWorkloadIdentity
	default:
		return tokenAuthUnsupportedAssertion
	}
}

func (e tokenClientAuthEvidence) matches(method string) bool {
	kind := e.kind()
	switch method {
	case "": // Pre-registration compatibility: still forbid mixed credentials.
		return kind != tokenAuthInvalid && kind != tokenAuthUnsupportedAssertion
	case "client_secret_basic":
		return kind == tokenAuthBasic
	case "client_secret_post":
		return kind == tokenAuthPost
	case "private_key_jwt":
		return kind == tokenAuthPrivateKeyJWT
	case ClientAuthWorkloadIdentity:
		return kind == tokenAuthWorkloadIdentity
	case ClientAuthTLS, ClientAuthSelfSignedTLS, "none":
		return kind == tokenAuthNone
	default:
		return false
	}
}

func inspectTokenClientAuth(r *http.Request, req *oauth.TokenRequest) (tokenClientAuthEvidence, string, string, bool) {
	evidence := tokenClientAuthEvidence{
		bodySecret: req.ClientSecret != "" || req.ClientSecretPresent || r.PostForm.Has("client_secret"),
		assertion: req.ClientAssertion != "" || req.ClientAssertionType != "" ||
			req.ClientAssertionPresent || req.ClientAssertionTypePresent ||
			r.PostForm.Has("client_assertion") || r.PostForm.Has("client_assertion_type"),
		assertionType: req.ClientAssertionType,
	}
	headers := r.Header.Values("Authorization")
	if len(headers) > 0 {
		if len(headers) != 1 {
			return tokenClientAuthEvidence{}, "", "", false
		}
		id, secret, ok := basicClientCreds(r)
		if !ok {
			return tokenClientAuthEvidence{}, "", "", false
		}
		return tokenClientAuthEvidence{
			basic: true, assertion: evidence.assertion, assertionType: evidence.assertionType,
		}, id, secret, true
	}
	return evidence, "", "", true
}

// resolveAssertedClientID verifies the selected RFC 7521 assertion. A
// private_key_jwt sub becomes ClientID; workload assertions retain the form
// ClientID because the cloud subject is mapped through client registration.
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

// verifyWorkloadIdentityClientAssertion binds a provider-verified cloud
// subject to the registered client. All failures collapse to invalid_client at
// the caller, preserving the endpoint's anti-enumeration contract.
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

// authenticateTokenClient identifies the client, then enforces tenant,
// registered authentication method, and resource gates. handled=true means a
// response was already written. Every authentication failure is oracle-safe.
func (s *Server) authenticateTokenClient(ctx HandlerContext, req *oauth.TokenRequest) (client *Client, basicAuthUsed bool, handled bool) {
	evidence, id, secret, ok := inspectTokenClientAuth(ctx.Request(), req)
	if !ok || evidence.kind() == tokenAuthInvalid {
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidClient))
		return nil, false, true
	}
	if evidence.basic {
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
	if !client.Active {
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidClient))
		return nil, basicAuthUsed, true
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ctx, ErrTenantMismatch))
		return nil, basicAuthUsed, true
	}

	if !s.verifyTokenClientAuth(ctx, client, req, evidence) {
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

// verifyTokenClientAuth treats token_endpoint_auth_method as a contract. A
// registered asymmetric or certificate client can never fall back to a secret.
func (s *Server) verifyTokenClientAuth(ctx HandlerContext, client *Client, req *oauth.TokenRequest, evidence tokenClientAuthEvidence) bool {
	method, kind := client.TokenEndpointAuthMethod, evidence.kind()
	if !evidence.matches(method) {
		return rejectTokenClientAuth(ctx)
	}
	if kind == tokenAuthPrivateKeyJWT || kind == tokenAuthWorkloadIdentity || method == "none" {
		return true
	}
	if method == ClientAuthTLS || method == ClientAuthSelfSignedTLS {
		if !s.authenticateMTLSClient(ctx, client) {
			return rejectTokenClientAuth(ctx)
		}
		return true
	}
	if err := s.clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
		return rejectTokenClientAuth(ctx)
	}
	return true
}

func rejectTokenClientAuth(ctx HandlerContext) bool {
	ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidClient))
	return false
}

// authenticateMTLSClient verifies the certificate binding required by the
// client's registered mTLS authentication method.
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

// mtlsCertRevoked applies the optional checker and fails open on checker
// outages, matching the existing availability policy.
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

func (s *Server) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	claims, _, err := s.validateAnyToken(ctx, token)
	if err == nil && claims != nil && claims.SID != "" {
		trackSessionActivity(ctx, s.sessionMgr, claims.SID)
	}
	return claims, err
}

// validateTokenPreChecks applies size and JWS algorithm bounds before an
// issuer performs expensive token parsing or signature verification.
func (s *Server) validateTokenPreChecks(token string) error {
	if s.maxTokenBytes > 0 && len(token) > s.maxTokenBytes {
		return fmt.Errorf("token exceeds max_token_bytes (%d)", s.maxTokenBytes)
	}
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
			if lifecycleErr := s.lifecycleClaimsError(ctx, claims); lifecycleErr != nil {
				return nil, "", lifecycleErr
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
