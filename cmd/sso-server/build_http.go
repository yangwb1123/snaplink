package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serveraccount"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildadmin"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverwebauthn"
	"github.com/yangwb1123/snaplink/config"
	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
	"github.com/yangwb1123/snaplink/interfaces/ssoext"
	"github.com/yangwb1123/snaplink/internal/handler"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/spi"
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
	if err := mountTenantQuotaProjectionHandler(cfg, a, logger); err != nil {
		return nil, err
	}
	if err := serveraccount.Mount(a.server, a.userProvider, a.recorder, logger); err != nil {
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

// buildAdminRESTMux registers the admin gRPC-gateway and composes the outer
// mux: the gateway's OWN exact route patterns (adminGatewayExactPaths) go
// through the admin middleware → gateway; everything else — including every
// admin path the SSO router owns, present and future — falls through the
// "/" catch-all to `base` (already admin-gated by wrapAdminAndBuildMux's
// caller). See serverbuildadmin.GatewayPaths' doc for why this is inverted
// from a subtree-plus-carve-outs scheme.
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

// adminGatewayExactPaths is the command-root view of the gateway's owned
// route patterns; the table itself (and the ServeMux rationale) lives in
// serverbuildadmin. Kept as a thin wrapper so the routing regression suite in
// package main (admin_gateway_routing_test.go) stays here beside the routes.
func adminGatewayExactPaths() []string {
	return serverbuildadmin.GatewayPaths()
}

// newAdminOuterMux delegates to serverbuildadmin.NewOuterMux — see its doc
// for the routing scheme.
func newAdminOuterMux(gatewayPaths []string, gated, base http.Handler) *http.ServeMux {
	return serverbuildadmin.NewOuterMux(gatewayPaths, gated, base)
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
	passwordDeleter, emailChangeRevoker := complianceCredentialStores(a)
	if err := mountComplianceRoutes(a.server, &complianceDeps{
		Users:                   a.userProvider,
		Sessions:                a.sessionMgr,
		Refresh:                 refreshIdx,
		Clients:                 a.clientStore,
		Consent:                 a.consentStore,
		MFAEnrollments:          a.mfaEnrollStore,
		PasswordReset:           a.passwordResetRevoker,
		EmailChange:             emailChangeRevoker,
		PasswordCredential:      passwordDeleter,
		Notifications:           a.server.NotificationStore(),
		NotificationPreferences: a.server.NotificationPreferenceStore(),
		Recorder:                a.recorder,
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
	factory, ok := ssoext.LookupSAMLHandlerFactory(cfg.SAML.Handler)
	if !ok {
		return fmt.Errorf("saml.handler %q is not registered (call ssoext.RegisterSAMLHandlers from your forked main); registered: %v",
			cfg.SAML.Handler, ssoext.RegisteredSAMLHandlers())
	}
	set, err := factory(context.Background(), ssoext.SAMLServerDeps{
		IssuerForClient:       a.server.IssuerForClient,
		ClientStore:           a.clientStore,
		SessionManager:        a.sessionMgr,
		UserProvider:          a.userProvider,
		Issuer:                cfg.Server.Issuer,
		AuditRecorder:         a.recorder,
		Logger:                logger,
		RegisterAuthenticator: a.server.RegisterAuthenticator,
		ResumeFederatedLogin:  a.server.ResumeFederatedLogin,
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
	if err := adminv1.RegisterClientAdminServiceHandlerServer(ctx, gw, newClientAdminService(a)); err != nil {
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
	if err := registerLifecycleGateway(ctx, gw, a); err != nil {
		return err
	}
	if a.tenantStore != nil {
		if err := adminv1.RegisterTenantAdminServiceHandlerServer(ctx, gw, grpcserver.NewTenantAdminService(
			a.tenantStore, a.recorder, a.server.InvalidateTenantSuspensionCache,
			a.server.InvalidateTenantResidencyCache,
			a.server.RevokeTenantCredentials)); err != nil {
			return fmt.Errorf("gateway tenants: %w", err)
		}
	}
	return nil
}

func registerLifecycleGateway(ctx context.Context, gw *runtime.ServeMux, a *app) error {
	if a.snapshotPipeline != nil {
		if err := adminv1.RegisterSnapshotAdminServiceHandlerServer(ctx, gw, grpcserver.NewSnapshotAdminService(
			a.snapshotPipeline, a.snapshotStorage, a.snapshotter, a.snapshotRestorer, a.recorder, a.operationStore)); err != nil {
			return fmt.Errorf("gateway snapshots: %w", err)
		}
	}
	if a.releaseStore != nil {
		if err := adminv1.RegisterReleaseAdminServiceHandlerServer(ctx, gw, grpcserver.NewReleaseAdminService(
			a.releaseRegistry, a.releaseStore, a.recorder, a.operationStore)); err != nil {
			return fmt.Errorf("gateway releases: %w", err)
		}
	}
	if a.operationStore == nil {
		return nil
	}
	if err := adminv1.RegisterOperationAdminServiceHandlerServer(
		ctx, gw, grpcserver.NewOperationAdminService(a.operationStore)); err != nil {
		return fmt.Errorf("gateway operations: %w", err)
	}
	return nil
}

// runBootstrap constructs the file-backed Tracker, the AdminSeed bundle,
// and runs every built-in step that hasn't yet been applied. Errors are
// fatal — the operator must succeed at first-boot init before we accept
// any traffic.
