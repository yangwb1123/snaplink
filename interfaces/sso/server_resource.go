package sso

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/security"
)

func (f ClientCertExtractorFunc) ExtractClientCert(r *http.Request) (*x509.Certificate, bool) {
	return f(r)
}

// DefaultTLSPeerCertExtractor reads r.TLS.PeerCertificates[0] —
// the conventional path for direct TLS-terminated AS deployments
// where the Go server itself handles the handshake.
var DefaultTLSPeerCertExtractor ClientCertExtractor = ClientCertExtractorFunc(func(r *http.Request) (*x509.Certificate, bool) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, false
	}
	return r.TLS.PeerCertificates[0], true
})

// certificateThumbprintS256 computes RFC 8705 §3.1's
// `x5t#S256` — base64url-no-pad encoding of SHA-256(cert.Raw).
// cert MUST NOT be nil (callers gate on extractor's ok=false).
func certificateThumbprintS256(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyMTLSBearer enforces the resource-side half of RFC 8705 §3.
// Mirror of verifyDPoPBearer: when the access token carries
// cnf.x5t#S256, the inbound request MUST be on a TLS connection
// whose client cert has the matching SHA-256 thumbprint.
//
// Returns nil when:
//   - the token isn't mTLS-bound (no cnf.x5t#S256), OR
//   - the inbound cert thumbprint equals the bound value.
//
// Returns an error mapped to invalid_token (same wire shape as
// "invalid bearer") on mismatch — oracle-resistance: probes can't
// distinguish unbound from bound-but-mismatched tokens.
//
// Skips the check when no ClientCertExtractor is wired: an
// operator that minted mTLS-bound tokens via one deployment and
// then disabled the extractor would otherwise lock every bound
// token out. Operators changing mTLS posture should revoke
// existing bound tokens explicitly.
func (s *Server) verifyMTLSBearer(ctx HandlerContext, claims *TokenClaims) error {
	if claims == nil || claims.ConfirmationX5TS256 == "" {
		return nil
	}
	if s.clientCertExtractor == nil {
		// No extractor wired — see method doc for the
		// trade-off. The cert is still required on the wire
		// for any HTTP framework that auto-populates r.TLS,
		// just not validated.
		return nil
	}
	cert, ok := s.clientCertExtractor.ExtractClientCert(ctx.Request())
	if !ok || cert == nil {
		return errCertRequired
	}
	got := certificateThumbprintS256(cert)
	if got != claims.ConfirmationX5TS256 {
		return errCertThumbprintMismatch
	}
	return nil
}

// Sentinel errors so logging can distinguish the failure modes
// even though the wire collapses them to invalid_token.
var (
	errCertRequired           = httpError("mtls: token bound but no client cert presented")
	errCertThumbprintMismatch = httpError("mtls: cert thumbprint does not match cnf.x5t#S256")
)

// httpError is a stdlib-free sentinel-error type kept local to
// this file (avoids importing errors just for two constants).
type httpError string

func (e httpError) Error() string { return string(e) }

// applyPairwiseSubject computes the pairwise sub for (client, localSub)
// and persists the reverse mapping in the wired store. Returns the
// pairwise sub when the client opted in AND the store is wired;
// returns localSub unchanged otherwise. Called at every issuance
// path that mints a token whose sub claim the RP will see.
//
// Fail-open: when the store's MapPairwise fails, the function still
// returns the computed pairwise sub but logs the error via the
// supplied error sink. The token MINTS with the pairwise sub —
// resource-side lookups will fail (`invalid_token`) until the next
// successful map. The alternative (fail-closed) would block
// issuance, which is worse than a token whose userinfo path

// ProtectedResourceMetadata configures the RFC 9728 OAuth 2.0 Protected
// Resource Metadata document. All fields are optional overrides — sensible
// values are derived from server state at request time (resource = request
// base URL, authorization_servers = [issuer], jwks_uri, scopes, signing algs,
// mTLS/DPoP capability). Wire it with WithProtectedResourceMetadata; nil leaves
// the /.well-known/oauth-protected-resource route unmounted (byte-identical).
type ProtectedResourceMetadata struct {
	// Resource overrides the protected-resource identifier. Empty = the request
	// base URL (the common case: this server IS the resource).
	Resource string
	// AuthorizationServers overrides the AS issuer list. Empty = [server issuer].
	AuthorizationServers []string
	// ResourceName / ResourceDocumentation are optional human-facing fields.
	ResourceName          string
	ResourceDocumentation string
}

// protectedResourceMetadataDoc is the RFC 9728 §2 document. Fields are omitted
// when empty so the document advertises only what the server actually supports.
type protectedResourceMetadataDoc struct {
	Resource                          string   `json:"resource"`
	AuthorizationServers              []string `json:"authorization_servers,omitempty"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported            []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgValuesSupported []string `json:"resource_signing_alg_values_supported,omitempty"`
	TLSClientCertificateBound         bool     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	DPoPSigningAlgValuesSupported     []string `json:"dpop_signing_alg_values_supported,omitempty"`
	ResourceName                      string   `json:"resource_name,omitempty"`
	ResourceDocumentation             string   `json:"resource_documentation,omitempty"`
}

// WithProtectedResourceMetadata mounts the RFC 9728 OAuth 2.0 Protected Resource
// Metadata endpoint at /.well-known/oauth-protected-resource. Clients —
// especially MCP / AI-agent clients following the protected-resource discovery
// flow — fetch it to learn which authorization server issues tokens for this
// resource, the JWKS, supported scopes, and token-binding requirements. The
// document is derived from server state; prm supplies optional overrides. Not
// wired ⇒ the route is absent (byte-identical).
func WithProtectedResourceMetadata(prm ProtectedResourceMetadata) Option {
	return func(s *Server) {
		cp := prm
		s.protectedResourceMetadata = &cp
	}
}

// handleProtectedResourceMetadata serves the RFC 9728 document. Public (no
// auth) like the other /.well-known/* discovery endpoints. Derived per request
// so multi-host deployments get the right base URL.
func (s *Server) handleProtectedResourceMetadata(ctx HandlerContext) {
	prm := s.protectedResourceMetadata
	base := requestBaseURL(ctx.Request())

	resource := base
	if prm.Resource != "" {
		resource = prm.Resource
	}
	authServers := prm.AuthorizationServers
	if len(authServers) == 0 {
		authServers = []string{s.resolveIssuer(ctx)}
	}

	doc := protectedResourceMetadataDoc{
		Resource:                          resource,
		AuthorizationServers:              authServers,
		JWKSURI:                           base + PathJWKS,
		BearerMethodsSupported:            []string{"header"},
		ResourceSigningAlgValuesSupported: s.SigningAlgValues(ctx.Request().Context()),
		ResourceName:                      prm.ResourceName,
		ResourceDocumentation:             prm.ResourceDocumentation,
	}
	if snap := s.discoverySnapshot(ctx.Request().Context()); snap != nil && len(snap.scopes) > 0 {
		doc.ScopesSupported = snap.scopes
	}
	// Token-binding capability mirrors the discovery doc: mTLS-bound when a
	// client-cert extractor is wired, DPoP algs when DPoP can be used (the
	// asymmetric JWS allowlist).
	if s.clientCertExtractor != nil {
		doc.TLSClientCertificateBound = true
	}
	doc.DPoPSigningAlgValuesSupported = security.AsymmetricJWSAlgValues()

	ctx.JSON(http.StatusOK, doc)
}

// --- Endpoint-inventory candidates --------------------------------------
//
// Lives here (not a dedicated file) because interfaces/sso is at its frozen
// file-count ceiling (directory_fanout_test.go) — otherwise unrelated to
// the resource/PRM handling above; backs GET /api/v1/admin/endpoints.

// endpointInfo is one entry the runtime inventory (GET
// /api/v1/admin/endpoints) reports: the HTTP method, full wire path, and the
// FeatureGates surface (or "core" for an always-on route) it belongs to.
type endpointInfo struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Feature string `json:"feature"`
}

// endpointCandidate pairs an endpointInfo with the predicate deciding
// whether THIS server instance actually registered it. This table is
// presentation-only — Mount() (server_routes.go / server_routes_admin.go /
// server_federation.go) is the single source of truth for what gets wired;
// keep a candidate's `on` in sync with its route's real mount condition
// whenever that condition changes, or the inventory drifts from reality.
type endpointCandidate struct {
	endpointInfo
	on func(s *Server) bool
}

func alwaysOn(*Server) bool { return true }

// coreEndpointCandidates lists the routes mounted unconditionally by
// mountCoreOAuthOIDC — every deployment shape exposes these regardless of
// FeatureGates.
func coreEndpointCandidates() []endpointCandidate {
	core := []struct {
		method, path string
	}{
		{http.MethodGet, PathHealth},
		{http.MethodGet, PathStatus},
		{http.MethodGet, PathSetupStatus},
		{http.MethodPost, PathSetup},
		{http.MethodGet, PathJWKS},
		{http.MethodGet, PathOIDCDiscovery},
		{http.MethodGet, PathOAuthAuthorizationServerMetadata},
		{http.MethodPost, PathLogin},
		{http.MethodPost, PathMFAComplete},
		{http.MethodPost, PathSendCode},
		{http.MethodGet, PathCallback},
		{http.MethodPost, PathToken},
		{http.MethodPost, PathIntrospect},
		{http.MethodPost, PathRevoke},
		{http.MethodPost, PathRevokeAll},
		{http.MethodPost, PathDeviceCode},
		{http.MethodGet, PathDeviceVerify},
		{http.MethodPost, PathDeviceVerify},
		{http.MethodPost, PathPAR},
		{http.MethodPost, oauth.PathRegister},
		{http.MethodGet, oauth.PathRegisterByID},
		{http.MethodPut, oauth.PathRegisterByID},
		{http.MethodDelete, oauth.PathRegisterByID},
		{http.MethodPost, PathLogout},
	}
	out := make([]endpointCandidate, 0, len(core))
	for _, r := range core {
		out = append(out, endpointCandidate{endpointInfo{r.method, r.path, "core"}, alwaysOn})
	}
	return out
}

// gatedProtocolEndpointCandidates lists the routes each of OIDC/CIBA/CAEP/
// Federation directly control — see FeatureGates for what each surface covers.
func gatedProtocolEndpointCandidates() []endpointCandidate {
	return []endpointCandidate{
		{endpointInfo{http.MethodGet, PathUserInfo, "oidc"}, func(s *Server) bool { return s.oidcGateOn() }},
		{endpointInfo{http.MethodGet, PathEndSession, "oidc"}, func(s *Server) bool { return s.oidcGateOn() }},
		{endpointInfo{http.MethodGet, PathCheckSessionIframe, "oidc"}, func(s *Server) bool {
			return s.oidcGateOn() && s.sessionManagementEnabled
		}},
		{endpointInfo{http.MethodPost, PathBackchannelAuth, "ciba"}, func(s *Server) bool { return s.cibaGateOn() }},
		{endpointInfo{http.MethodGet, PathSSFConfig, "caep"}, func(s *Server) bool {
			return s.caepGateOn()
		}},
		{endpointInfo{http.MethodPost, PathSSFReceive, "caep"}, func(s *Server) bool {
			return s.caepGateOn() && s.caepReceiver != nil
		}},
		{endpointInfo{http.MethodGet, PathProtectedResourceMetadata, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.protectedResourceMetadata != nil
		}},
		{endpointInfo{http.MethodGet, PathFederationEntityConfig, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.federationEntity != nil
		}},
		{endpointInfo{http.MethodGet, PathFederationResolve, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.federationEntity != nil && s.federationEntity.Resolver().Enabled()
		}},
		{endpointInfo{http.MethodGet, PathFederationFetch, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.federationEntity != nil && s.federationEntity.HasSubordinates()
		}},
		{endpointInfo{http.MethodGet, PathFederationList, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.federationEntity != nil && s.federationEntity.HasSubordinates()
		}},
		{endpointInfo{http.MethodGet, PathFederationTrustMarkStatus, "federation"}, func(s *Server) bool {
			return s.federationGateOn()
		}},
		{endpointInfo{http.MethodGet, PathFederationResolve, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.federationEntity != nil && s.federationEntity.Resolver().Enabled()
		}},
		{endpointInfo{http.MethodGet, PathHomeRealm, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.connectionStore != nil
		}},
		{endpointInfo{http.MethodPost, PathHomeRealm, "federation"}, func(s *Server) bool {
			return s.federationGateOn() && s.connectionStore != nil
		}},
	}
}

// selfServiceEndpointCandidates approximates mountCoreOAuthOIDC's
// unauthenticated password-reset/signup block plus mountSelfServiceProfile +
// mountSelfServiceCredentials. Some deeply-nested sub-conditions (e.g. the
// TOTPEnrollmentWriter type assertion, signup's verification-mode branch)
// are simplified to their outer store check — the inventory can show a
// self-service sub-route as live in a narrow misconfiguration where the real
// route is not (never the reverse: SelfService off always hides all of
// these). Good enough for "what surface is exposed", not a byte-exact mirror.
func selfServiceEndpointCandidates() []endpointCandidate {
	on := func(cond func(s *Server) bool) func(s *Server) bool {
		return func(s *Server) bool { return s.selfServiceGateOn() && cond(s) }
	}
	hasBoth := func(a, b func(s *Server) bool) func(s *Server) bool {
		return func(s *Server) bool { return a(s) && b(s) }
	}
	return []endpointCandidate{
		{endpointInfo{http.MethodPost, PathForgotPassword, "self_service"}, on(func(s *Server) bool {
			return s.passwordResetStore != nil && s.passwordCredentialStore != nil
		})},
		{endpointInfo{http.MethodPost, PathResetPassword, "self_service"}, on(func(s *Server) bool {
			return s.passwordResetStore != nil && s.passwordCredentialStore != nil
		})},
		{endpointInfo{http.MethodPost, PathSignup, "self_service"}, on(func(s *Server) bool {
			return s.signupEnabled && s.userProvider != nil && s.passwordCredentialStore != nil
		})},
		{endpointInfo{http.MethodPost, PathVerifyEmail, "self_service"}, on(func(s *Server) bool {
			return s.signupEnabled && s.emailVerificationStore != nil
		})},
		{endpointInfo{http.MethodGet, PathMyPermissions, "self_service"}, func(s *Server) bool { return s.selfServiceGateOn() }},
		{endpointInfo{http.MethodGet, PathMySessions, "self_service"}, on(func(s *Server) bool { return s.sessionMgr != nil })},
		{endpointInfo{http.MethodGet, PathMyConsents, "self_service"}, on(func(s *Server) bool { return s.consentStore != nil })},
		{endpointInfo{http.MethodGet, PathMyOrganizations, "self_service"}, on(func(s *Server) bool { return s.tenantUserStore != nil })},
		{endpointInfo{http.MethodGet, PathMe, "self_service"}, on(func(s *Server) bool { return s.userProvider != nil })},
		{endpointInfo{http.MethodPost, PathMyPassword, "self_service"}, on(func(s *Server) bool { return s.passwordCredentialStore != nil })},
		{endpointInfo{http.MethodGet, PathMyMFA, "self_service"}, on(func(s *Server) bool { return s.mfaEnrollmentStore != nil })},
		{endpointInfo{http.MethodPost, PathMyWebAuthnRegisterBegin, "self_service"}, on(func(s *Server) bool { return s.webauthnRegistrar != nil })},
		{endpointInfo{http.MethodGet, PathMyDataExport, "self_service"}, on(func(s *Server) bool { return s.dataExporter != nil })},
		{endpointInfo{http.MethodPost, PathMyAccountErase, "self_service"}, on(func(s *Server) bool { return s.accountEraser != nil })},
		{endpointInfo{http.MethodPost, PathMyEmailChange, "self_service"}, on(hasBoth(
			func(s *Server) bool { return s.emailChangeStore != nil && s.emailChangeSender != nil },
			func(s *Server) bool { return s.userProvider != nil },
		))},
	}
}

// adminAPIEndpointCandidates lists the /api/v1/admin/* (+ the co-mounted
// /api/v1/clients/:id) routes, each gated on AdminAPI AND its own store —
// mirrors mountAdminSurface's group-level gate ANDed with the per-block
// conditions above / in server_federation.go.
func adminAPIEndpointCandidates() []endpointCandidate {
	prefix := PathAPIPrefix
	on := func(cond func(s *Server) bool) func(s *Server) bool {
		return func(s *Server) bool { return s.adminAPIGateOn() && cond(s) }
	}
	return []endpointCandidate{
		{endpointInfo{http.MethodGet, prefix + PathClientByID, "admin_api"}, func(s *Server) bool { return s.adminAPIGateOn() }},
		{endpointInfo{http.MethodGet, prefix + PathAdminEndpoints, "admin_api"}, func(s *Server) bool { return s.adminAPIGateOn() }},
		{endpointInfo{http.MethodGet, prefix + PathAuditEvents, "admin_api"}, on(func(s *Server) bool { return s.auditAPI && s.auditor != nil })},
		{endpointInfo{http.MethodGet, prefix + PathNetPolicies, "admin_api"}, on(func(s *Server) bool { return s.netAPI && s.netStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathTenantUsage, "admin_api"}, on(func(s *Server) bool { return s.usageAggregator != nil })},
		{endpointInfo{http.MethodPost, prefix + PathBackup, "admin_api"}, on(func(s *Server) bool { return len(s.backupSources) > 0 })},
		{endpointInfo{http.MethodGet, prefix + PathAdminTokens, "admin_api"}, on(func(s *Server) bool { return s.adminTokenStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminSessions, "admin_api"}, on(func(s *Server) bool { return s.sessionMgr != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminSessionsLinked, "admin_api"}, func(s *Server) bool { return s.adminAPIGateOn() }},
		{endpointInfo{http.MethodGet, prefix + PathAdminUserConsents, "admin_api"}, on(func(s *Server) bool { return s.consentStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminUserMFA, "admin_api"}, on(func(s *Server) bool { return s.mfaEnrollmentStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminUserLifecycle, "admin_api"}, on(func(s *Server) bool { return s.userLifecycleStore != nil && s.userProvider != nil })},
		{endpointInfo{http.MethodPost, prefix + PathAdminUserPassword, "admin_api"}, on(func(s *Server) bool { return s.passwordCredentialStore != nil })},
		{endpointInfo{http.MethodPost, prefix + PathAdminUserEmail, "admin_api"}, on(func(s *Server) bool { return s.userProvider != nil })},
		{endpointInfo{http.MethodDelete, prefix + PathAdminUserDeviceSecrets, "admin_api"}, on(func(s *Server) bool { return s.deviceSecretStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminUserPasswordResetTokens, "admin_api"}, on(func(s *Server) bool { return s.passwordResetStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminUserEmailChangeTokens, "admin_api"}, on(func(s *Server) bool { return s.emailChangeStore != nil })},
		{endpointInfo{http.MethodPost, prefix + PathAdminAccountLockoutClear, "admin_api"}, on(func(s *Server) bool { return s.accountLockout != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminConnections, "admin_api"}, on(func(s *Server) bool { return s.connectionStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminTenantMembers, "admin_api"}, on(func(s *Server) bool { return s.tenantUserStore != nil })},
		{endpointInfo{http.MethodPost, prefix + PathAdminTenantInvitations, "admin_api"}, on(func(s *Server) bool { return s.invitationStore != nil })},
		{endpointInfo{http.MethodGet, PathAuthzPolicyBundle, "admin_api"}, on(func(s *Server) bool { return s.permissions != nil })},
		{endpointInfo{http.MethodGet, PathStorageHealth, "admin_api"}, on(func(s *Server) bool { return len(s.storageHealthSources) > 0 })},
		{endpointInfo{http.MethodGet, PathAdminFederationHealth, "admin_api"}, on(func(s *Server) bool { return s.federationHealth != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminWebhookSubscriptions, "admin_api"}, on(func(s *Server) bool { return s.webhookEngine != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminWebhookDeadLetters, "admin_api"}, on(func(s *Server) bool { return s.webhookEngine != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminComplianceDataMap, "admin_api"}, func(s *Server) bool { return s.adminAPIGateOn() }},
		{endpointInfo{http.MethodGet, prefix + PathAdminComplianceSOC2Evidence, "admin_api"}, on(func(s *Server) bool { return s.auditor != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminComplianceConsents, "admin_api"}, on(func(s *Server) bool { return s.consentStore != nil && s.userProvider != nil })},
		{endpointInfo{http.MethodPost, prefix + PathAdminComplianceRetentionSweep, "admin_api"}, on(func(s *Server) bool { return s.dataRetention.Enabled })},
		// Active ITDR threat-policy CRUD (opt-in WithThreatPolicyStore).
		{endpointInfo{http.MethodGet, prefix + PathAdminThreatPolicies, "admin_api"}, on(func(s *Server) bool { return s.threatPolicyStore != nil })},
		{endpointInfo{http.MethodGet, prefix + PathAdminThreatPolicyByID, "admin_api"}, on(func(s *Server) bool { return s.threatPolicyStore != nil })},
		{endpointInfo{http.MethodPut, prefix + PathAdminThreatPolicyByID, "admin_api"}, on(func(s *Server) bool { return s.threatPolicyStore != nil })},
		{endpointInfo{http.MethodDelete, prefix + PathAdminThreatPolicyByID, "admin_api"}, on(func(s *Server) bool { return s.threatPolicyStore != nil })},
	}
}

// endpointCandidates is the full table the inventory endpoint filters.
// Rebuilt per call (cheap — a few dozen struct literals) rather than a
// package-level var so it never risks aliasing mutable predicate state.
func endpointCandidates() []endpointCandidate {
	var all []endpointCandidate
	all = append(all, coreEndpointCandidates()...)
	all = append(all, gatedProtocolEndpointCandidates()...)
	all = append(all, selfServiceEndpointCandidates()...)
	all = append(all, adminAPIEndpointCandidates()...)
	return all
}
