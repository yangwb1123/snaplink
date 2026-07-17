package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/snaplink/sso/cmd/sso-server/serverwebauthn"
	"github.com/snaplink/sso/config"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/spi"
)

func buildHTTPHandler(cfg *config.Config, a *app, logger spi.Logger) (http.Handler, error) {
	base := a.server.Handler()
	if err := mountWebAuthnHandler(cfg, a, logger); err != nil {
		return nil, err
	}
	if err := mountPushCallbackHandler(cfg, a, logger); err != nil {
		return nil, err
	}
	if err := mountComplianceAndSCIM(cfg, a, logger); err != nil {
		return nil, err
	}
	if err := mountSAMLHandler(cfg, a, logger); err != nil {
		return nil, err
	}
	if err := mountDRStatusHandler(cfg, a, logger); err != nil {
		return nil, err
	}
	return wrapAdminAndBuildMux(cfg, a, base, logger)
}

// pathAdminDRStatus is a read-only observability endpoint, mounted the same
// way as the other admin-gated GET surfaces (tenant usage, sessions): it
// lives under /api/v1/admin/ so admin.IsProtectedPath gates it via the
// path-prefix check applied to the WHOLE router below, not by any route-
// registration-time wiring.
const pathAdminDRStatus = "/api/v1/admin/dr/status"

// mountDRStatusHandler registers GET /api/v1/admin/dr/status when dr.enabled
// wired a readiness aggregate. Mounted AFTER a.server.Handler() so the
// router exists (same requirement as the WebAuthn/push/compliance/SCIM/SAML
// late-bound routes above — see Handle's doc comment).
//
// Only when the operator explicitly opts in via dr.gate_readiness does this
// ALSO fold the same verdict into /readyz — default is report-only: a
// stale/missing DR replica never fails /readyz or blocks auth traffic on its
// own (docs/dr-framework.md).
func mountDRStatusHandler(cfg *config.Config, a *app, logger spi.Logger) error {
	if a.drReadiness == nil {
		return nil
	}
	if err := a.server.Handle(http.MethodGet, pathAdminDRStatus, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a.drReadiness.Status(r.Context()))
	}); err != nil {
		return err
	}
	if cfg.DR.GateReadiness {
		a.server.AddReadyCheck("dr", a.drReadiness.ReadyCheck)
	}
	logger.Info("dr: admin status endpoint mounted", "path", pathAdminDRStatus, "gate_readiness", cfg.DR.GateReadiness)
	return nil
}

// wrapAdminAndBuildMux is the tail of buildHTTPHandler split out to keep it
// under the function-length budget: wraps base with the admin middleware so
// every /api/v1/admin/* (and /api/v1/audit,compliance,scim,netpolicy) path
// gets the same Bearer + scope gate, then composes the admin gRPC-gateway
// mux on top when both admin and the REST gateway are enabled.
func wrapAdminAndBuildMux(cfg *config.Config, a *app, base http.Handler, logger spi.Logger) (http.Handler, error) {
	// Wrap base with the admin middleware so /api/v1/audit/* and
	// /api/v1/netpolicy/policies* + /classify get the same Bearer +
	// scope gate as /api/v1/admin/*. isAdminProtectedPath inside
	// AdminMiddleware decides per-path; everything else passes
	// through untouched. When admin is disabled, audit + netpolicy
	// stay open (single-tenant / firewall-protected story) and we
	// log a warning so the operator notices.
	if a.adminMW != nil {
		base = a.adminMW.HTTPMiddleware(base)
	} else if cfg.Audit.APIEnabled || (cfg.Network.Enabled && cfg.Network.APIEnabled) {
		logger.Error("admin disabled: /api/v1/audit and /api/v1/netpolicy/policies endpoints will be served UNAUTHENTICATED. Production deployments MUST enable admin so bearer auth is enforced.")
	}
	if a.adminMW == nil || !cfg.Admin.APIRESTEnabled {
		return base, nil
	}
	return buildAdminRESTMux(a, base, cfg, logger)
}

// adminGatewayExactPaths lists every URL PATTERN the admin gRPC-gateway (see
// registerAdminGateway) actually serves — derived from the .proto http
// annotations under proto/admin/v1/*.proto. Reproduce with:
//
//	grep -rhn "WithHTTPPathPattern(" gen/proto/admin/v1/*.pb.gw.go | \
//	  grep -oP '(?<=WithHTTPPathPattern\(")[^"]+' | sort -u
//
// Registering the gateway ONLY at these literal patterns — instead of the
// whole /api/v1/admin/ subtree — lets every other admin route (which grows
// continuously; see interfaces/sso/server_routes_admin.go) fall through the
// outer mux's "/" catch-all to `base` by default, instead of requiring an
// ad-hoc carve-out per new SSO-router route. That old scheme silently
// swallowed new routes into the gateway's blanket 404 whenever a carve-out
// was forgotten — it was forgotten at least twice (bulk-revoke, commit
// fdebea60, and the local-user CRUD collision fixed alongside this change).
//
// Several proto RPCs share one URL SHAPE under a different path-variable
// name (e.g. Update's "{client.id}" vs Get/Delete's "{id}" both bind the
// same single wildcard segment — grpc-gateway's OWN internal mux resolves
// the per-method dispatch). Go's http.ServeMux (1.22+ pattern matching) only
// cares about the STRUCTURAL shape — segment count + literal-vs-wildcard —
// so each shape is listed ONCE; the variable name is irrelevant to routing.
//
// IMPORTANT, verified empirically (see TestAdminGatewayExactPaths_ValidServeMuxSyntax):
// grpc-gateway's "custom verb" shapes — "{id}:pin", "{id}:rollback",
// "{id}:restore", "{id}:set-status" (a colon-suffix GLUED to the SAME
// wildcard segment) — are NOT valid Go http.ServeMux pattern syntax.
// mux.Handle panics at registration with "bad wildcard segment (must end
// with '}')": Go's wildcard segment must be the ENTIRE segment, nothing may
// follow "}" before the next "/". Registering the PLAIN "{id}" pattern (also
// needed for that resource's Get/Delete) is sufficient WITHOUT a separate
// entry: Go's ServeMux treats a colon as ordinary segment text, so a request
// for ".../releases/abc:pin" structurally matches "/api/v1/admin/releases/{id}"
// just like ".../releases/abc" does. The request then reaches `gated`
// UNMODIFIED, where grpc-gateway's OWN internal pattern compiler (which DOES
// support the colon-verb convention) re-resolves the exact RPC from the full
// path + method — exactly as it already did before this change, when the
// whole /api/v1/admin/ subtree was forwarded to it. This routing fix only
// changes which requests reach the gateway's ServeHTTP, never how the
// gateway resolves a request once it gets there. "releases:current" (a bare
// literal, no wildcard) has no such restriction and is listed as-is.
//
// The "tokens" and "users" families are NOT full subtrees: the SSO router
// owns most of their sub-paths (token portfolio/expiring/suspicious/usage/
// bulk-revoke/policies, and every users/{id}/... surface except the bare
// CRUD + session-list), so only the gateway's own exact shapes are listed.
func adminGatewayExactPaths() []string {
	paths := adminGatewayResourcePaths()
	return append(paths, adminGatewayTokenAndUserPaths()...)
}

// adminGatewayResourcePaths covers the clients/domains/keys/permissions/
// releases/snapshots/tenants families — split out of adminGatewayExactPaths
// purely to stay under the function-length budget (§0.1); see that
// function's doc for the shared rationale and the custom-verb caveat these
// "{id}"-only releases/snapshots/tenants entries rely on.
func adminGatewayResourcePaths() []string {
	return []string{
		// clients — proto/admin/v1/clients.proto
		"/api/v1/admin/clients",
		"/api/v1/admin/clients/{id}",
		"/api/v1/admin/clients/{id}/approve",
		"/api/v1/admin/clients/{id}/reject",
		"/api/v1/admin/clients/{id}/rotate-secret",
		// domains — proto/admin/v1/tenants.proto
		"/api/v1/admin/domains",
		"/api/v1/admin/domains/{hostname}",
		// keys — proto/admin/v1/keys.proto
		"/api/v1/admin/keys",
		"/api/v1/admin/keys/rotate",
		// permissions — proto/admin/v1/permissions.proto
		"/api/v1/admin/permissions/{client_id}/assignments",
		"/api/v1/admin/permissions/{client_id}/assignments/{user_id}",
		"/api/v1/admin/permissions/{client_id}/assignments/{user_id}/unassign",
		"/api/v1/admin/permissions/{client_id}/menus",
		"/api/v1/admin/permissions/{client_id}/roles",
		"/api/v1/admin/permissions/{client_id}/roles/{role_code}",
		// releases — proto/admin/v1/releases.proto. "{id}" also catches the
		// grpc-gateway custom-verb shapes "{id}:pin"/"{id}:rollback" — see
		// adminGatewayExactPaths' doc; do NOT add those separately (panics).
		"/api/v1/admin/releases",
		"/api/v1/admin/releases:current",
		"/api/v1/admin/releases/{id}",
		// snapshots — proto/admin/v1/snapshots.proto. "{id}" also catches
		// "{id}:restore".
		"/api/v1/admin/snapshots",
		"/api/v1/admin/snapshots/{id}",
		// tenants — proto/admin/v1/tenants.proto. "{id}" also catches
		// "{id}:set-status".
		"/api/v1/admin/tenants",
		"/api/v1/admin/tenants/{id}",
	}
}

// adminGatewayTokenAndUserPaths covers the tokens/users families — NOT full
// subtrees, since the SSO router owns most of their sub-paths. Split out of
// adminGatewayExactPaths purely to stay under the function-length budget.
func adminGatewayTokenAndUserPaths() []string {
	return []string{
		// tokens — proto/admin/v1/tokens.proto — ONLY these three shapes.
		// tokens/portfolio, tokens/subjects/*, tokens/expiring,
		// tokens/suspicious, tokens/usage, tokens/bulk-revoke, and
		// token-policies are ALL SSO-router-owned; never add them here.
		"/api/v1/admin/tokens/revoke",
		"/api/v1/admin/tokens/sessions",
		"/api/v1/admin/tokens/temp",
		// users — proto/admin/v1/users.proto — ONLY the bare CRUD + session-
		// list shapes. Every other users/{id}/... sub-path (mfa, consents,
		// password, email, device-secrets, refresh-tokens, password-reset-
		// tokens, email-change-tokens, lifecycle, recovery-codes) is
		// SSO-router-owned; never add them here.
		"/api/v1/admin/users",
		"/api/v1/admin/users/{id}",
		"/api/v1/admin/users/{id}/sessions",
	}
}

// buildAdminRESTMux registers the admin gRPC-gateway and composes the outer
// mux: the gateway's OWN exact route patterns (adminGatewayExactPaths) go
// through the admin middleware → gateway; everything else — including every
// admin path the SSO router owns, present and future — falls through the
// "/" catch-all to `base` (already admin-gated by wrapAdminAndBuildMux's
// caller). See adminGatewayExactPaths' doc for why this is inverted from a
// subtree-plus-carve-outs scheme.
func buildAdminRESTMux(a *app, base http.Handler, cfg *config.Config, logger spi.Logger) (http.Handler, error) {
	gw := runtime.NewServeMux()
	if err := registerAdminGateway(context.Background(), gw, a); err != nil {
		return nil, err
	}
	paths := adminGatewayExactPaths()
	logger.Info("admin REST gateway mounted", "prefix", adminAPIPathPrefix, "routes", len(paths))

	gated := a.adminMW.HTTPMiddleware(gw)
	// Apply the same request body-size cap as the main SSO middleware chain so
	// admin write endpoints (JSON create/update) are covered by the operator's
	// configured limit. Without this the gRPC-gateway routes would accept
	// arbitrarily large bodies, bypassing the cap. A limit of 0 means the
	// operator has not configured one — skip wrapping to stay byte-identical.
	if n := cfg.Security.BodyLimit.MaxBytes; n > 0 {
		gated = handler.BodyLimitMiddleware(n, nil)(gated)
	}
	return newAdminOuterMux(paths, gated, base), nil
}

// newAdminOuterMux composes the final outer mux from the gateway's exact
// owned patterns and the two handlers: `gated` (admin-gated gRPC-gateway)
// answers exactly those patterns, `base` (the admin-gated SSO router)
// answers everything else via the "/" catch-all. Split out of
// buildAdminRESTMux so the routing table itself — which patterns resolve to
// which handler — is unit-testable without constructing a full *app (see
// admin_gateway_routing_test.go).
func newAdminOuterMux(gatewayPaths []string, gated, base http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	for _, p := range gatewayPaths {
		mux.Handle(p, gated)
	}
	mux.Handle("/", base)
	return mux
}

// mountWebAuthnHandler mounts the WebAuthn ceremony routes on the SSO router
// itself so they share the same middleware stack (tracing, metrics, rate-limit,
// CORS) the built-in endpoints use. Mounted AFTER Handler() so the router has
// been initialized — Handle errors otherwise. No-op when WebAuthn is off.
func mountWebAuthnHandler(cfg *config.Config, a *app, logger spi.Logger) error {
	if a.webauthnHelper == nil {
		return nil
	}
	deps := &serverwebauthn.WebAuthnDeps{
		Helper:            a.webauthnHelper,
		ClientStore:       a.clientStore,
		TokenIssuers:      a.tokenIssuers,
		DefaultStrat:      cfg.Server.DefaultTokenStrategy,
		RefreshTokenStore: a.refreshTokenStore,
		RefreshTokenTTL:   a.refreshTokenTTL,
		IDTokenIssuer:     a.idTokenIssuer,
		Metrics:           a.metrics,
		AuditRecorder:     a.recorder,
	}
	// Data-residency on the WebAuthn login mint path: wire the region
	// resolver + the server's context-free ResidencyDecision seam ONLY
	// when region is configured (mirrors how WithRegionMiddleware /
	// WithTenantResidencyCheck are conditionally wired in buildApp). Both
	// left nil otherwise ⇒ no residency check for WebAuthn (byte-identical
	// to a non-residency deployment). The /auth/login path is already
	// residency-gated in-pipeline; this closes the raw-handler WebAuthn gap.
	if a.regionResolver != nil {
		deps.RegionResolver = a.regionResolver
		deps.ResidencyDecision = a.server.ResidencyDecision
	}
	if err := serverwebauthn.MountWebAuthnRoutes(a.server, deps); err != nil {
		return fmt.Errorf("mount webauthn: %w", err)
	}
	logger.Info("webauthn routes mounted",
		"register_begin", serverwebauthn.PathWebAuthnRegistrationBegin,
		"register_finish", serverwebauthn.PathWebAuthnRegistrationFinish,
		"login_begin", serverwebauthn.PathWebAuthnLoginBegin,
		"login_finish", serverwebauthn.PathWebAuthnLoginFinish,
	)
	return nil
}

// mountPushCallbackHandler mounts the reference push approval callback. Operators
// with a custom gateway leave callback.enabled=false and SetStatus directly.
func mountPushCallbackHandler(cfg *config.Config, a *app, logger spi.Logger) error {
	if !cfg.MFA.Provider.Push.Callback.Enabled {
		return nil
	}
	if a.pushApprovalStore == nil {
		logger.Info("push callback.enabled=true but push backend not configured — callback mount skipped")
		return nil
	}
	callbackDeps, err := buildPushCallbackDeps(cfg.MFA.Provider.Push.Callback, a.pushApprovalStore, a.pushNotify, logger)
	if err != nil {
		return fmt.Errorf("push callback: %w", err)
	}
	if err := mountPushCallbackRoute(a.server, callbackDeps); err != nil {
		return fmt.Errorf("mount push callback: %w", err)
	}
	logger.Info("push approval callback mounted at /push/approval/:id/:decision",
		"bearer_token_required", callbackDeps.BearerToken != "",
		"ip_allowlist_size", len(callbackDeps.AllowedCIDRs),
		"channel_notify", callbackDeps.Notify != nil)
	return nil
}

// mountComplianceAndSCIM mounts the GDPR subject export/erase + SCIM 2.0 routes.
// Both are destructive / PII-leaking, so only mounted when admin auth is enabled
// (IsProtectedPath gates /api/v1/compliance/ + /api/v1/scim/ like /admin/).
func mountComplianceAndSCIM(cfg *config.Config, a *app, logger spi.Logger) error {
	if a.adminMW == nil {
		return nil
	}
	var refreshIdx oauth.RefreshTokenSubjectIndex
	if idx, ok := a.refreshTokenStore.(oauth.RefreshTokenSubjectIndex); ok {
		refreshIdx = idx
	}
	if err := mountComplianceRoutes(a.server, &complianceDeps{
		Users:          a.userProvider,
		Sessions:       a.sessionMgr,
		Refresh:        refreshIdx,
		Clients:        a.clientStore,
		Consent:        a.consentStore,
		MFAEnrollments: a.mfaEnrollStore,
		PasswordReset:  a.passwordResetRevoker,
		Recorder:       a.recorder,
	}); err != nil {
		return fmt.Errorf("mount compliance: %w", err)
	}
	logger.Info("compliance routes mounted",
		"export", complianceUsersPrefix+"{id}"+complianceExportSuffix,
		"erase", complianceUsersPrefix+"{id}"+complianceEraseSuffix)

	// /Groups additionally requires a permissions.Provider (a SCIM group maps
	// onto a role), opted into via scim.groups.enabled.
	var scimGroups *scimGroupDeps
	if cfg.SCIM.Groups.Enabled {
		if a.provider == nil {
			return fmt.Errorf("scim.groups.enabled requires permissions.enabled (a SCIM group maps onto a permissions role)")
		}
		scimGroups = &scimGroupDeps{provider: a.provider, clientID: cfg.SCIM.Groups.GroupClientID}
	}
	if err := mountSCIMRoutes(a.server, a.userProvider, a.recorder, scimGroups); err != nil {
		return fmt.Errorf("mount scim: %w", err)
	}
	logger.Info("scim routes mounted", "base", scimBasePath, "groups", scimGroups != nil)
	return nil
}

// mountSAMLHandler builds + mounts the SAML 2.0 surface when saml.handler names a
// registered factory (the SAML/XML/DSig deps live in the operator's forked main,
// never in this module's go.mod). cfg.SAML.Handler == "" ⇒ a no-op. SAML
// endpoints are SP/IdP-public, so — like the WebAuthn ceremony — they mount
// OUTSIDE the admin gate.
func mountSAMLHandler(cfg *config.Config, a *app, logger spi.Logger) error {
	if cfg.SAML.Handler == "" {
		return nil
	}
	factory, ok := lookupSAMLHandlerFactory(cfg.SAML.Handler)
	if !ok {
		return fmt.Errorf("saml.handler %q is not registered (call RegisterSAMLHandlers from your forked main); registered: %v",
			cfg.SAML.Handler, RegisteredSAMLHandlers())
	}
	set, err := factory(context.Background(), SAMLServerDeps{
		IssuerForClient:       a.server.IssuerForClient,
		ClientStore:           a.clientStore,
		SessionManager:        a.sessionMgr,
		UserProvider:          a.userProvider,
		Issuer:                cfg.Server.Issuer,
		AuditRecorder:         a.recorder,
		Logger:                logger,
		RegisterAuthenticator: a.server.RegisterAuthenticator,
	})
	if err != nil {
		return fmt.Errorf("saml handler %q: %w", cfg.SAML.Handler, err)
	}
	if set == nil {
		return nil
	}
	for _, h := range set.Handlers {
		if err := a.server.Handle(h.Method, h.Path, h.Handler); err != nil {
			return fmt.Errorf("mount saml %s %s: %w", h.Method, h.Path, err)
		}
	}
	for _, auth := range set.Authenticators {
		a.server.RegisterAuthenticator(auth)
	}
	if set.ReadyCheck != nil {
		a.server.AddReadyCheck("saml-"+cfg.SAML.Handler, set.ReadyCheck)
	}
	logger.Info("saml routes mounted",
		"handler", cfg.SAML.Handler,
		"routes", len(set.Handlers),
		"authenticators", len(set.Authenticators),
		"ready_check", set.ReadyCheck != nil)
	return nil
}

// registerAdminGateway registers every admin gRPC-gateway service onto gw. The
// snapshot / release / tenant services are conditional on their store being
// wired (nil ⇒ unmounted, byte-identical to a build without them).
func registerAdminGateway(ctx context.Context, gw *runtime.ServeMux, a *app) error {
	if err := adminv1.RegisterClientAdminServiceHandlerServer(ctx, gw, grpcserver.NewClientAdminService(a.clientStore, a.recorder, a.server.InvalidateDiscoveryCache, a.server.InvalidateClientCache)); err != nil {
		return fmt.Errorf("gateway clients: %w", err)
	}
	if err := adminv1.RegisterUserAdminServiceHandlerServer(ctx, gw, grpcserver.NewUserAdminService(a.userProvider, a.sessionMgr, a.recorder)); err != nil {
		return fmt.Errorf("gateway users: %w", err)
	}
	if err := adminv1.RegisterTokenAdminServiceHandlerServer(ctx, gw, grpcserver.NewTokenAdminService(grpcserver.TokenAdminConfig{
		Sessions:            a.sessionMgr,
		TempStore:           a.tempStore,
		Issuers:             a.tokenIssuers,
		RevokeAcrossIssuers: a.server.RevokeAcrossIssuers,
		Recorder:            a.recorder,
	})); err != nil {
		return fmt.Errorf("gateway tokens: %w", err)
	}
	if err := adminv1.RegisterPermissionAdminServiceHandlerServer(ctx, gw, grpcserver.NewPermissionAdminService(
		a.provider, a.recorder,
		func(_ context.Context, id string) { a.server.InvalidateAuthzPolicyBundleCache(id) })); err != nil {
		return fmt.Errorf("gateway permissions: %w", err)
	}
	if a.keyAdmin != nil {
		if err := adminv1.RegisterKeyAdminServiceHandlerServer(ctx, gw, a.keyAdmin); err != nil {
			return fmt.Errorf("gateway keys: %w", err)
		}
	}
	if a.snapshotPipeline != nil {
		if err := adminv1.RegisterSnapshotAdminServiceHandlerServer(ctx, gw, grpcserver.NewSnapshotAdminService(
			a.snapshotPipeline, a.snapshotStorage, a.snapshotter, a.snapshotRestorer, a.recorder)); err != nil {
			return fmt.Errorf("gateway snapshots: %w", err)
		}
	}
	if a.releaseStore != nil {
		if err := adminv1.RegisterReleaseAdminServiceHandlerServer(ctx, gw, grpcserver.NewReleaseAdminService(
			a.releaseRegistry, a.releaseStore, a.recorder)); err != nil {
			return fmt.Errorf("gateway releases: %w", err)
		}
	}
	if a.tenantStore != nil {
		if err := adminv1.RegisterTenantAdminServiceHandlerServer(ctx, gw, grpcserver.NewTenantAdminService(
			a.tenantStore, a.recorder, a.server.InvalidateTenantSuspensionCache,
			a.server.InvalidateTenantResidencyCache,
			func(ctx context.Context, id string) { _, _ = a.server.RevokeTenantRefreshTokens(ctx, id) })); err != nil {
			return fmt.Errorf("gateway tenants: %w", err)
		}
	}
	return nil
}

// runBootstrap constructs the file-backed Tracker, the AdminSeed bundle,
// and runs every built-in step that hasn't yet been applied. Errors are
// fatal — the operator must succeed at first-boot init before we accept
// any traffic.
