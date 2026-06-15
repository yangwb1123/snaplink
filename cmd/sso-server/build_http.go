package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/snaplink/sso"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/spi"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/grpcserver"
)

func buildHTTPHandler(cfg *config.Config, a *app, logger spi.Logger) (http.Handler, error) {
	base := a.server.Handler()
	// WebAuthn ceremony routes mount on the SSO router itself so they
	// share the same middleware stack (tracing, metrics, rate-limit,
	// CORS) the built-in endpoints use. Mount AFTER Handler() so the
	// router has been initialized — Handle errors otherwise.
	if a.webauthnHelper != nil {
		deps := &webauthnDeps{
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
		if err := mountWebAuthnRoutes(a.server, deps); err != nil {
			return nil, fmt.Errorf("mount webauthn: %w", err)
		}
		logger.Info("webauthn routes mounted",
			"register_begin", pathWebAuthnRegistrationBegin,
			"register_finish", pathWebAuthnRegistrationFinish,
			"login_begin", pathWebAuthnLoginBegin,
			"login_finish", pathWebAuthnLoginFinish,
		)
	}
	// Push approval callback (reference impl). Operators with a
	// custom gateway leave callback.enabled=false and SetStatus
	// directly from their own handler.
	if cfg.MFA.Provider.Push.Callback.Enabled && a.pushApprovalStore != nil {
		callbackDeps, err := buildPushCallbackDeps(cfg.MFA.Provider.Push.Callback, a.pushApprovalStore, a.pushNotify, logger)
		if err != nil {
			return nil, fmt.Errorf("push callback: %w", err)
		}
		if err := mountPushCallbackRoute(a.server, callbackDeps); err != nil {
			return nil, fmt.Errorf("mount push callback: %w", err)
		}
		logger.Info("push approval callback mounted at /push/approval/:id/:decision",
			"bearer_token_required", callbackDeps.BearerToken != "",
			"ip_allowlist_size", len(callbackDeps.AllowedCIDRs),
			"channel_notify", callbackDeps.Notify != nil)
	} else if cfg.MFA.Provider.Push.Callback.Enabled {
		logger.Info("push callback.enabled=true but push backend not configured — callback mount skipped")
	}
	// GDPR subject export/erase routes. Destructive (erase) + PII-
	// leaking (export), so only mounted when admin auth is enabled —
	// IsProtectedPath gates /api/v1/compliance/ the same as /admin/.
	if a.adminMW != nil {
		var refreshIdx oauth.RefreshTokenSubjectIndex
		if idx, ok := a.refreshTokenStore.(oauth.RefreshTokenSubjectIndex); ok {
			refreshIdx = idx
		}
		if err := mountComplianceRoutes(a.server, &complianceDeps{
			Users:    a.userProvider,
			Sessions: a.sessionMgr,
			Refresh:  refreshIdx,
			Clients:  a.clientStore,
			Recorder: a.recorder,
		}); err != nil {
			return nil, fmt.Errorf("mount compliance: %w", err)
		}
		logger.Info("compliance routes mounted",
			"export", complianceUsersPrefix+"{id}"+complianceExportSuffix,
			"erase", complianceUsersPrefix+"{id}"+complianceEraseSuffix)

		// SCIM 2.0 User provisioning (RFC 7643/7644). Lists/replaces/
		// deletes the whole user directory, so — like compliance — only
		// mounted when admin auth is enabled; IsProtectedPath gates
		// /api/v1/scim/ the same as /api/v1/admin/. /Groups additionally
		// requires a permissions.Provider (a SCIM group maps onto a role),
		// opted into via scim.groups.enabled.
		var scimGroups *scimGroupDeps
		if cfg.SCIM.Groups.Enabled {
			if a.provider == nil {
				return nil, fmt.Errorf("scim.groups.enabled requires permissions.enabled (a SCIM group maps onto a permissions role)")
			}
			scimGroups = &scimGroupDeps{provider: a.provider, clientID: cfg.SCIM.Groups.GroupClientID}
		}
		if err := mountSCIMRoutes(a.server, a.userProvider, a.recorder, scimGroups); err != nil {
			return nil, fmt.Errorf("mount scim: %w", err)
		}
		logger.Info("scim routes mounted", "base", scimBasePath, "groups", scimGroups != nil)
	}
	// SAML 2.0 (cluster: external/forked SAML module). When saml.handler
	// names a registered SAMLHandlerFactory (the operator registered it from
	// their forked main via RegisterSAMLHandlers — the SAML/XML/DSig deps
	// live there, never in this module's go.mod), build the SAML surface and
	// mount it on the SSO router. cfg.SAML.Handler == "" ⇒ this whole block
	// is a no-op (byte-identical to a build without SAML): no lookup, no
	// routes, no authenticator. The signing key is borrowed by the factory
	// off the JWT issuer's CryptoSigner() accessor (a stdlib crypto.Signer
	// for XML-DSig), reusing the JWKS key so SP metadata matches. SAML
	// endpoints (e.g. /saml/metadata, the ACS callback) are SP/IdP-public,
	// so — like the WebAuthn ceremony — they mount OUTSIDE the admin gate;
	// the admin-middleware wrap below only intercepts admin-prefixed paths.
	if cfg.SAML.Handler != "" {
		factory, ok := lookupSAMLHandlerFactory(cfg.SAML.Handler)
		if !ok {
			return nil, fmt.Errorf("saml.handler %q is not registered (call RegisterSAMLHandlers from your forked main); registered: %v",
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
			return nil, fmt.Errorf("saml handler %q: %w", cfg.SAML.Handler, err)
		}
		if set != nil {
			for _, h := range set.Handlers {
				if err := a.server.Handle(h.Method, h.Path, h.Handler); err != nil {
					return nil, fmt.Errorf("mount saml %s %s: %w", h.Method, h.Path, err)
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
		}
	}
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
	gw := runtime.NewServeMux()
	ctx := context.Background()
	if err := adminv1.RegisterClientAdminServiceHandlerServer(ctx, gw, grpcserver.NewClientAdminService(a.clientStore, a.recorder, a.server.InvalidateDiscoveryCache, a.server.InvalidateClientCache)); err != nil {
		return nil, fmt.Errorf("gateway clients: %w", err)
	}
	if err := adminv1.RegisterUserAdminServiceHandlerServer(ctx, gw, grpcserver.NewUserAdminService(a.userProvider, a.sessionMgr, a.recorder)); err != nil {
		return nil, fmt.Errorf("gateway users: %w", err)
	}
	if err := adminv1.RegisterTokenAdminServiceHandlerServer(ctx, gw, grpcserver.NewTokenAdminService(grpcserver.TokenAdminConfig{
		Sessions:  a.sessionMgr,
		TempStore: a.tempStore,
		Issuers:   a.tokenIssuers,
		Recorder:  a.recorder,
	})); err != nil {
		return nil, fmt.Errorf("gateway tokens: %w", err)
	}
	if err := adminv1.RegisterPermissionAdminServiceHandlerServer(ctx, gw, grpcserver.NewPermissionAdminService(
		a.provider, a.recorder,
		func(_ context.Context, id string) { a.server.InvalidateAuthzPolicyBundleCache(id) })); err != nil {
		return nil, fmt.Errorf("gateway permissions: %w", err)
	}
	if a.snapshotPipeline != nil {
		if err := adminv1.RegisterSnapshotAdminServiceHandlerServer(ctx, gw, grpcserver.NewSnapshotAdminService(
			a.snapshotPipeline, a.snapshotStorage, a.snapshotter, a.snapshotRestorer, a.recorder)); err != nil {
			return nil, fmt.Errorf("gateway snapshots: %w", err)
		}
	}
	if a.releaseStore != nil {
		if err := adminv1.RegisterReleaseAdminServiceHandlerServer(ctx, gw, grpcserver.NewReleaseAdminService(
			a.releaseRegistry, a.releaseStore, a.recorder)); err != nil {
			return nil, fmt.Errorf("gateway releases: %w", err)
		}
	}
	if a.tenantStore != nil {
		if err := adminv1.RegisterTenantAdminServiceHandlerServer(ctx, gw, grpcserver.NewTenantAdminService(
			a.tenantStore, a.recorder, a.server.InvalidateTenantSuspensionCache,
			a.server.InvalidateTenantResidencyCache,
			func(ctx context.Context, id string) { _, _ = a.server.RevokeTenantRefreshTokens(ctx, id) })); err != nil {
			return nil, fmt.Errorf("gateway tenants: %w", err)
		}
	}
	logger.Info("admin REST gateway mounted", "prefix", adminAPIPathPrefix)

	// Outer mux: admin paths go through middleware → gateway; everything
	// else falls through to the SSO runtime handler.
	gated := a.adminMW.HTTPMiddleware(gw)
	mux := http.NewServeMux()
	mux.Handle(adminAPIPathPrefix, gated)
	// The authz policy-bundle export is a custom HTTP handler on the SSO
	// router (it needs the Server's bundle cache + provider), not a
	// gRPC-gateway route — but its path lives under /api/v1/admin/, which
	// the line above sends to the gateway. Route this exact path back to
	// `base` (already admin-gated at line ~665); ServeMux's longest-match
	// makes the exact pattern win over the /api/v1/admin/ subtree.
	if a.provider != nil {
		mux.Handle(sso.PathAuthzPolicyBundle, base)
	}
	mux.Handle("/", base)
	return mux, nil
}

// runBootstrap constructs the file-backed Tracker, the AdminSeed bundle,
// and runs every built-in step that hasn't yet been applied. Errors are
// fatal — the operator must succeed at first-boot init before we accept
// any traffic.
