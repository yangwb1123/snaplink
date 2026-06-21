package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildauthn"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildplatform"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildsign"
	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	"github.com/snaplink/sso/cmd/sso-server/serverwebauthn"
	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/authenticators/webauthn"
	webauthnsqlite "github.com/snaplink/sso/domains/authenticators/webauthnsqlite"
	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/sso"
)

// wireSelfServicePassword builds the self-service password store and the
// authenticators that depend on it, then wires signup, password reset, and
// data-export self-service endpoints.
func (b *appBuilder) wireSelfServicePassword() error {
	cfg, logger := b.cfg, b.logger
	// Self-service password store. When wired it seeds login from the YAML
	// users and mounts /me/password; the SAME instance backs both the verifier
	// (login) and the change endpoint so a changed password takes effect on the
	// next login. Empty backend = nil = YAML-only verifier (byte-identical).
	passwordStore, err := serverbuildstore.BuildPasswordCredentialStore(cfg.SelfService.Password)
	if err != nil {
		return fmt.Errorf("self_service password store: %w", err)
	}
	b.passwordStore = passwordStore

	auths, tempStore, totpAuth, totpEnrollStore, err := serverbuildauthn.BuildAuthenticators(cfg, logger, passwordStore, b.userProvider)
	if err != nil {
		return fmt.Errorf("authenticators: %w", err)
	}
	b.tempStore = tempStore
	b.totpAuth = totpAuth
	b.totpEnrollStore = totpEnrollStore
	for _, ath := range auths {
		b.opts = append(b.opts, sso.WithAuthenticator(ath))
	}
	// Self-service MFA enrollment-store wiring is deferred until after the
	// WebAuthn store is built (below) so /me/mfa can compose TOTP secrets AND
	// WebAuthn passkeys into one view. The TOTP enroller is wired there too.
	if passwordStore != nil {
		b.opts = append(b.opts, sso.WithPasswordCredentialStore(passwordStore))
		logger.Info("self-service password change enabled", "backend", cfg.SelfService.Password.Backend)
	}
	// Opt-in self-service signup (POST /auth/register). Needs the password store
	// (to set the new account's password). Default-off — open signup is an abuse
	// surface; enable deliberately for B2C.
	if cfg.SelfService.Signup {
		if passwordStore == nil {
			return errors.New("self_service.signup requires self_service.password to be enabled")
		}
		b.opts = append(b.opts, sso.WithSelfServiceSignup())
		logger.Info("self-service signup enabled (/auth/register)")
	}
	if err := b.wirePasswordReset(); err != nil {
		return err
	}
	// GDPR Art. 15 self-service data export (/me/data-export), reusing the same
	// exporter stores as the admin compliance route. Opt-in.
	if cfg.SelfService.DataExport && b.userProvider != nil {
		b.opts = append(b.opts, selfServiceDataExportOption(b.userProvider, b.sessionMgr))
		logger.Info("self-service data export enabled (/me/data-export)")
	}
	return nil
}

// wirePasswordReset wires the unauthenticated forgot-password flow: the
// reset-token store plus the default identifier/delivery resolvers.
func (b *appBuilder) wirePasswordReset() error {
	cfg, logger := b.cfg, b.logger
	passwordResetStore, err := serverbuildstore.BuildPasswordResetStore(cfg.SelfService.PasswordReset)
	if err != nil {
		return fmt.Errorf("self_service password_reset store: %w", err)
	}
	if passwordResetStore == nil || b.passwordStore == nil {
		return nil
	}
	up := b.userProvider
	b.opts = append(b.opts,
		sso.WithPasswordResetStore(passwordResetStore, cfg.SelfService.PasswordReset.TTL),
		sso.WithPasswordResetResolver(func(ctx context.Context, identifier string) (string, error) {
			// Default: treat the identifier as the userID (resolve via the
			// directory). Deployments that log in by email/username supply
			// their own resolver via the SDK.
			u, gerr := up.GetByID(ctx, identifier)
			if gerr != nil || u == nil {
				return "", nil
			}
			return u.ID, nil
		}),
		sso.WithPasswordResetDeliveryResolver(func(ctx context.Context, userID string) (string, error) {
			u, gerr := up.GetByID(ctx, userID)
			if gerr != nil || u == nil {
				return "", nil
			}
			return u.Email, nil
		}),
	)
	logger.Info("forgot-password store wired; provide a PasswordResetSender via the SDK to deliver tokens (delivery is a no-op until then)",
		"backend", cfg.SelfService.PasswordReset.Backend)
	return nil
}

// wireGeoRegionRisk wires the geo provider, the serving-region resolver +
// residency check, and the risk scorer — in that order so risk rules see geo.
func (b *appBuilder) wireGeoRegionRisk() error {
	cfg, logger := b.cfg, b.logger
	geoProvider, err := serverbuildstore.BuildGeoProvider(cfg, logger)
	if err != nil {
		return fmt.Errorf("geo provider: %w", err)
	}
	if geoProvider != nil {
		b.opts = append(b.opts, sso.WithGeoProvider(geoProvider))
		if cfg.Geo.LookupTimeout > 0 {
			b.opts = append(b.opts, sso.WithGeoMiddlewareOptions(sso.GeoMiddlewareOptions{
				Timeout: cfg.Geo.LookupTimeout,
			}))
		}
	}

	b.wireRegion()

	// Risk scorer wired AFTER geo so country-based rules see the
	// populated GeoInfo on RiskRequest.Geo. When risk.enabled is
	// false, serverbuildplatform.BuildRiskScorer returns nil and cmd skips
	// WithRiskScorer entirely — zero overhead on /auth/login.
	riskScorer, err := serverbuildplatform.BuildRiskScorer(&cfg.Risk, logger)
	if err != nil {
		return fmt.Errorf("risk scorer: %w", err)
	}
	if riskScorer != nil {
		b.opts = append(b.opts, sso.WithRiskScorer(riskScorer))
	}
	return nil
}

// wireRegion wires the serving-region resolver + residency enforcement.
// serverbuildstore.BuildRegionResolver returns nil when region is unconfigured → the middleware
// is NOT installed and the residency check stays inert (byte-identical). When
// configured, the middleware-level AllowedRegions backstop mirrors the header
// resolver's allowlist, and the residency engine enforces the tenant's policy.
func (b *appBuilder) wireRegion() {
	cfg := b.cfg
	regionResolver := serverbuildstore.BuildRegionResolver(cfg)
	b.regionResolver = regionResolver
	if regionResolver == nil {
		return
	}
	var allowed []region.ID
	if len(cfg.Region.AllowedRegions) > 0 {
		allowed = make([]region.ID, len(cfg.Region.AllowedRegions))
		for i, r := range cfg.Region.AllowedRegions {
			allowed[i] = region.ID(r)
		}
	}
	b.opts = append(b.opts, sso.WithRegionMiddleware(regionResolver, region.MiddlewareOptions{
		AllowedRegions: allowed,
	}))
	b.opts = append(b.opts, sso.WithTenantResidencyCheck(cfg.Region.ResidencyCheckCacheTTL))
	b.logger.Info("region residency: enabled",
		"serving_region", cfg.Region.ServingRegion,
		"header_name", cfg.Region.HeaderName,
		"allowed_regions", cfg.Region.AllowedRegions,
	)
}

// wireWebAuthnMFA builds the shared WebAuthn helper (before MFA so step-up can
// wrap it), the composite MFA enrollment store, passkey registrar, the MFA
// orchestration provider, and the optional push-approval prune loop.
func (b *appBuilder) wireWebAuthnMFA() error {
	cfg, logger := b.cfg, b.logger
	// WebAuthn helper built here (before MFA so mfa.provider.kind=
	// webauthn can wrap the same helper instance, sharing UserStore +
	// SessionStore + RP config across primary auth and step-up). Same
	// /readyz wiring as the other SQLite-substrate components.
	webauthnHelper, webauthnUsers, webauthnSessions, err := serverwebauthn.BuildWebAuthnHelper(cfg.WebAuthn, logger)
	if err != nil {
		return fmt.Errorf("webauthn: %w", err)
	}
	b.webauthnHelper = webauthnHelper
	b.webauthnUsers = webauthnUsers
	if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, webauthnUsers, "webauthn_users", webauthnsqlite.UsersMaxVersion()); err != nil {
		return fmt.Errorf("schema check webauthn_users: %w", err)
	}
	if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, webauthnSessions, "webauthn_sessions", webauthnsqlite.SessionsMaxVersion()); err != nil {
		return fmt.Errorf("schema check webauthn_sessions: %w", err)
	}
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-webauthn-users", webauthnUsers)
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-webauthn-sessions", webauthnSessions)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-webauthn-users", webauthnUsers)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-webauthn-sessions", webauthnSessions)

	b.wireMFAEnrollment()
	// Authenticated self-service passkey registration over the SAME ceremony
	// Helper, so a passkey added at /me/mfa/webauthn surfaces in /me/mfa and
	// works at login. Bearer-bound (registers only to the caller's own account).
	if webauthnHelper != nil {
		b.opts = append(b.opts, sso.WithWebAuthnRegistrar(webauthn.NewRegistrar(webauthnHelper)))
		logger.Info("self-service passkey registration enabled (/me/mfa/webauthn)")
	}
	return b.wireMFAProvider()
}

// wireMFAEnrollment composes every available factor source (TOTP secrets +
// WebAuthn passkeys) into one MFAEnrollmentStore for /me/mfa.
func (b *appBuilder) wireMFAEnrollment() {
	logger := b.logger
	var mfaEnrollStores []sso.MFAEnrollmentStore
	if b.totpEnrollStore != nil {
		mfaEnrollStores = append(mfaEnrollStores, b.totpEnrollStore)
	}
	if b.webauthnUsers != nil {
		mfaEnrollStores = append(mfaEnrollStores, webauthn.NewMFAEnrollmentAdapter(b.webauthnUsers))
	}
	n := len(mfaEnrollStores)
	if n == 0 {
		return
	}
	store := mfaEnrollStores[0]
	if n > 1 {
		store = defaultimpl.NewCompositeMFAEnrollmentStore(mfaEnrollStores...)
	}
	b.opts = append(b.opts, sso.WithMFAEnrollmentStore(store))
	if b.totpEnrollStore != nil {
		b.opts = append(b.opts, sso.WithTOTPEnroller(authenticators.NewTOTPEnroller(b.totpAuth)))
	}
	logger.Info("self-service MFA management enabled (/me/mfa)", "factor_sources", n)
}

// wireMFAProvider builds the MFA orchestration provider + challenge store and
// the optional SQLite push-approval prune loop.
func (b *appBuilder) wireMFAProvider() error {
	cfg, logger := b.cfg, b.logger
	// MFA orchestration wired AFTER the risk scorer so the wire-up
	// order matches the runtime gating order (Risk emits
	// DecisionRequireMFA → MFA orchestration consumes it). Without
	// both Provider + Store opts, RequireMFA decays to Allow — same
	// back-compat fall-through embedders see when they ship a Risk
	// scorer ahead of MFA.
	mfaProvider, mfaStore, mfaTTL, _, pushApprovalStore, pushNotify, err := serverbuildstore.BuildMFA(cfg.MFA, b.totpAuth, b.webauthnHelper, logger)
	if err != nil {
		return fmt.Errorf("mfa: %w", err)
	}
	b.pushApprovalStore = pushApprovalStore
	b.pushNotify = pushNotify
	if mfaProvider != nil && mfaStore != nil {
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, mfaStore, "mfa_challenges", sqlitestores.MFAChallengesMaxVersion()); err != nil {
			return fmt.Errorf("schema check mfa_challenges: %w", err)
		}
		b.opts = append(b.opts, sso.WithMFAProvider(mfaProvider))
		b.opts = append(b.opts, sso.WithMFAChallengeStore(mfaStore, mfaTTL))
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-mfa-challenges", mfaStore)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-mfa-challenges", mfaStore)
	}
	// When push MFA wired with SQLite backend, surface the store
	// handle for /readyz wiring + the optional PruneExpired loop
	// (operators wanting bounded approval-table growth without
	// running external cron).
	if pushApprovalStore != nil {
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, pushApprovalStore, "push_approvals", sqlitestores.PushApprovalsMaxVersion()); err != nil {
			return fmt.Errorf("schema check push_approvals: %w", err)
		}
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-push-approvals", pushApprovalStore)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-push-approvals", pushApprovalStore)
		if pi := cfg.MFA.Provider.Push.PruneInterval; pi > 0 {
			pruneCtx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			b.pushPruneCancel = cancel
			b.pushPruneDone = done
			go serverbuildsign.RunPushApprovalPrune(pruneCtx, done, pushApprovalStore, pi, logger, b.metricsRegistry)
			logger.Info("push approvals: prune scheduler enabled", "interval", pi)
		}
	}
	return nil
}

// wireAnomaly wires the async behavioral-detection pipeline (off the request
// hot path) plus its SQLite readiness checks.
func (b *appBuilder) wireAnomaly() error {
	cfg, logger := b.cfg, b.logger
	anomalyRT, err := buildAnomaly(cfg.Anomaly, b.recorder, b.metricsRegistry, logger)
	if err != nil {
		return fmt.Errorf("anomaly: %w", err)
	}
	b.anomalyRT = anomalyRT
	if anomalyRT == nil || anomalyRT.runner == nil {
		return nil
	}
	b.opts = append(b.opts, sso.WithAnomalyRunner(anomalyRT.runner))
	if anomalyRT.recentSQLite != nil {
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, anomalyRT.recentSQLite, "recent_login", sqlitestores.RecentLoginMaxVersion()); err != nil {
			return fmt.Errorf("schema check recent_login: %w", err)
		}
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-anomaly-recent-logins", anomalyRT.recentSQLite)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-anomaly-recent-logins", anomalyRT.recentSQLite)
	}
	if anomalyRT.ipFailSQLite != nil {
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, anomalyRT.ipFailSQLite, "ip_failure_counter", sqlitestores.IPFailureCounterMaxVersion()); err != nil {
			return fmt.Errorf("schema check ip_failure_counter: %w", err)
		}
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-anomaly-ip-failures", anomalyRT.ipFailSQLite)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-anomaly-ip-failures", anomalyRT.ipFailSQLite)
	}
	logger.Info("anomaly detection: enabled",
		"recent_login_backend", cfg.Anomaly.RecentLogin.Backend,
		"ip_failure_backend", cfg.Anomaly.IPFailure.Backend,
	)
	return nil
}
