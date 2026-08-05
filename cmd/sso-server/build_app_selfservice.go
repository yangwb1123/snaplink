package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildauthn"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildplatform"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildsign"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverwebauthn"
	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/authenticators/webauthn"
	webauthnsqlite "github.com/yangwb1123/snaplink/domains/authenticators/webauthnsqlite"
	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/domains/threataction"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/trust"
)

// wireSelfServicePassword builds the self-service password store and the
// authenticators that depend on it, then wires signup/reset/export.
func (b *appBuilder) wireSelfServicePassword() error {
	cfg, logger := b.cfg, b.logger
	// Self-service password store. When wired it seeds login from the YAML
	// users and mounts /me/password; the SAME instance backs both the verifier
	// (login) and the change endpoint so a changed password takes effect on the
	// next login. Empty backend = nil = YAML-only verifier (byte-identical).
	passwordStore, err := serverbuildstore.BuildPasswordCredentialStore(cfg.SelfService.Password, b.pgDB, b.pgDialect)
	if err != nil {
		return fmt.Errorf("self_service password store: %w", err)
	}
	b.passwordStore = passwordStore

	auths, tempStore, totpAuth, totpEnrollStore, err := serverbuildauthn.BuildAuthenticatorsDurableWithLinker(cfg, logger, passwordStore, b.userProvider, b.redis, b.pgDB, b.pgDialect, b.identityLinker)
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
	if err := b.wireSelfServiceSignup(); err != nil {
		return err
	}
	if err := b.wireEmailSenders(); err != nil {
		return err
	}
	if err := b.wirePasswordReset(); err != nil {
		return err
	}
	// GDPR Art. 15 self-service data export (/me/data-export), reusing the same
	// exporter stores as the admin compliance route. Opt-in. Extra (consent +
	// MFA enrollments) is late-bound in finalize() once those stores wire.
	if cfg.SelfService.DataExport && b.userProvider != nil {
		b.dataExporter = newSelfServiceExporter(b.userProvider, b.sessionMgr)
		b.opts = append(b.opts, sso.WithSelfServiceDataExport(b.dataExporter))
		logger.Info("self-service data export enabled (/me/data-export)")
	}
	return nil
}

// wireSelfServiceSignup opts in the unauthenticated self-service
// registration endpoint POST /auth/register. Default-off — open signup is
// an abuse surface; enable deliberately for B2C.
func (b *appBuilder) wireSelfServiceSignup() error {
	if !b.cfg.SelfService.Signup {
		return nil
	}
	if b.passwordStore == nil {
		return errors.New("self_service.signup requires self_service.password to be enabled")
	}
	b.opts = append(b.opts, sso.WithSelfServiceSignup())
	b.logger.Info("self-service signup enabled (/auth/register)")
	return nil
}

// wirePasswordReset wires the unauthenticated forgot-password flow.
func (b *appBuilder) wirePasswordReset() error {
	cfg, logger := b.cfg, b.logger
	passwordResetStore, err := serverbuildstore.BuildPasswordResetStore(cfg.SelfService.PasswordReset, b.redis)
	if err != nil {
		return fmt.Errorf("self_service password_reset store: %w", err)
	}
	if passwordResetStore == nil || b.passwordStore == nil {
		return nil
	}
	// Retained for the GDPR eraser (lateBindComplianceStores, compliance_routes.go).
	if revoker, ok := passwordResetStore.(core.PasswordResetRevoker); ok {
		b.passwordResetRevoker = revoker
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
	if b.emailSender != nil {
		logger.Info("forgot-password store wired; delivery via the built-in SMTP sender",
			"backend", cfg.SelfService.PasswordReset.Backend)
	} else {
		logger.Info("forgot-password store wired; provide a PasswordResetSender via the SDK to deliver tokens (delivery is a no-op until then)",
			"backend", cfg.SelfService.PasswordReset.Backend)
	}
	return nil
}

// wireEmailSenders wires SMTP token delivery and the optional notification inbox.
func (b *appBuilder) wireEmailSenders() error {
	sender, err := serverbuildplatform.BuildEmailSender(b.cfg.SMTP, b.logger)
	if err != nil {
		return fmt.Errorf("smtp sender: %w", err)
	}
	if sender != nil {
		b.emailSender = sender
		b.opts = append(b.opts, sso.WithPasswordResetSender(sender), sso.WithEmailVerificationSender(sender),
			sso.WithEmailChangeSender(sender), sso.WithInvitationSender(sender))
		b.logger.Info("built-in SMTP email delivery enabled", "host", b.cfg.SMTP.Host, "port", b.cfg.SMTP.Port)
	}
	notificationOpts, err := serverbuildplatform.BuildNotifications(
		b.cfg.Notifications, b.userProvider, b.sessionMgr, sender, b.metricsRegistry, b.logger, b.redis)
	if err != nil {
		return fmt.Errorf("notifications: %w", err)
	}
	b.opts = append(b.opts, notificationOpts...)
	return nil
}

// wireGeoRegionRisk wires geo, region resolver + residency check (with its
// optional policy store), and the risk scorer — in that order.
func (b *appBuilder) wireGeoRegionRisk() error {
	cfg, logger := b.cfg, b.logger
	geoProvider, err := serverbuildstore.BuildGeoProvider(cfg, logger)
	if err != nil {
		return fmt.Errorf("geo provider: %w", err)
	}
	if geoProvider != nil {
		b.opts = append(b.opts, sso.WithGeoProvider(geoProvider))
		b.wireGeoMiddlewareOptions()
	}

	if err := b.wireRegion(); err != nil {
		return err
	}

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

// wireGeoMiddlewareOptions wires the geo middleware's Timeout/IPExtractor/
// OnError. Only called when a geo provider is configured.
func (b *appBuilder) wireGeoMiddlewareOptions() {
	cfg, logger := b.cfg, b.logger
	geoOpts := sso.GeoMiddlewareOptions{
		Timeout: cfg.Geo.LookupTimeout,
		OnError: func(err error) {
			logger.Error("geo lookup failed", "error", err)
		},
	}
	if len(cfg.Security.TrustedProxies.CIDRs) > 0 {
		// TrustedProxiesConfig's doc comment promises the validated
		// real client IP feeds "rate-limiting AND geo enrichment" —
		// without this, geo (and any RiskConfig.CountryDenyList rule
		// that reads RiskRequest.Geo) falls back to
		// geo.DefaultIPExtractor, which trusts the raw, leftmost
		// X-Forwarded-For hop verbatim. That lets any caller — even
		// one that legitimately traverses the configured trusted
		// proxy — steer the resolved country by prepending an
		// arbitrary forged hop, regardless of trusted_proxies being
		// configured. Route geo through the same TrustedProxies-
		// validated IP the rate limiter already uses.
		geoOpts.IPExtractor = trustedProxyIPExtractor
	}
	// Always wired (not gated on LookupTimeout/TrustedProxies being set) so
	// OnError reaches the operator's logger regardless of those other
	// knobs -- a geo-provider outage is fail-open by design, but should
	// never be silent. Timeout/IPExtractor keep their exact prior
	// zero-value/nil defaults when the corresponding condition doesn't hold.
	b.opts = append(b.opts, sso.WithGeoMiddlewareOptions(geoOpts))
}

// trustedProxyIPExtractor resolves the geo (and, transitively, risk-scorer)
// client IP from the TrustedProxies-validated address instead of trusting
// forwarded headers directly. middleware.RealClientIP degrades to
// r.RemoteAddr — never a raw, attacker-supplied X-Forwarded-For hop — when
// TrustedProxies middleware didn't run, so this is never less safe than
// geo.DefaultIPExtractor even on a request that bypasses the chain.
func trustedProxyIPExtractor(r *http.Request) net.IP {
	return net.ParseIP(middleware.RealClientIP(r))
}

// wireRegion wires the serving-region resolver + residency enforcement +
// the optional region.PolicyStore (nil resolver → inert, byte-identical).
func (b *appBuilder) wireRegion() error {
	cfg := b.cfg
	regionResolver := serverbuildstore.BuildRegionResolver(cfg, b.peerTrust)
	b.regionResolver = regionResolver
	if regionResolver == nil {
		return nil
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
		OnError: func(r *http.Request, err error) {
			b.logger.Error("region resolution failed", "path", r.URL.Path, "error", err)
		},
	}))
	b.opts = append(b.opts, sso.WithTenantResidencyCheck(cfg.Region.ResidencyCheckCacheTTL))
	policyStore, err := serverbuildstore.BuildRegionPolicyStore(cfg, b.logger)
	if err != nil {
		return err
	}
	b.opts = append(b.opts, sso.WithResidencyPolicyStore(policyStore)) // nil store = tenant-row-only
	b.logger.Info("region residency: enabled",
		"serving_region", cfg.Region.ServingRegion,
		"header_name", cfg.Region.HeaderName,
		"allowed_regions", cfg.Region.AllowedRegions,
	)
	return nil
}

// wireWebAuthnMFA builds the shared WebAuthn helper (before MFA so step-up
// can wrap it), the composite MFA store, passkey registrar, orchestration
// provider, and the optional push-approval prune loop.
func (b *appBuilder) wireWebAuthnMFA() error {
	cfg, logger := b.cfg, b.logger
	// WebAuthn helper built here (before MFA so mfa.provider.kind=
	// webauthn can wrap the same helper instance, sharing UserStore +
	// SessionStore + RP config across primary auth and step-up). Same
	// /readyz wiring as the other SQLite-substrate components.
	webauthnHelper, webauthnUsers, webauthnSessions, err := serverwebauthn.BuildWebAuthnHelperDurable(cfg.WebAuthn, logger, b.pgDB, string(b.pgDialect), b.redis)
	if err != nil {
		return fmt.Errorf("webauthn: %w", err)
	}
	b.webauthnHelper = webauthnHelper
	b.webauthnUsers = webauthnUsers
	// CheckSQLiteSchema probes sqlite_master, so skip it for the postgres-backed
	// user store (which exposes DB() and runs its own advisory-locked migration
	// at construction) — otherwise the sqlite_master query returns 42P01 on
	// Postgres and aborts boot. Mirrors the identity (build_app_core.go) and
	// pairwise (build_app_oidc.go) postgres guards.
	if !strings.EqualFold(strings.TrimSpace(cfg.WebAuthn.Storage.Users.Backend), "postgres") {
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, webauthnUsers, "webauthn_users", webauthnsqlite.UsersMaxVersion()); err != nil {
			return fmt.Errorf("schema check webauthn_users: %w", err)
		}
	}
	if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, webauthnSessions, "webauthn_sessions", webauthnsqlite.SessionsMaxVersion()); err != nil {
		return fmt.Errorf("schema check webauthn_sessions: %w", err)
	}
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-webauthn-users", webauthnUsers)
	b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-webauthn-sessions", webauthnSessions)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-webauthn-users", webauthnUsers)
	b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-webauthn-sessions", webauthnSessions)

	b.wireMFAEnrollment()
	if err := b.wirePasskeyPolicy(); err != nil {
		return err
	}
	// Authenticated self-service passkey registration over the SAME ceremony
	// Helper, so a passkey added at /me/mfa/webauthn surfaces in /me/mfa and
	// works at login. Bearer-bound (registers only to the caller's own account).
	if webauthnHelper != nil {
		b.opts = append(b.opts, sso.WithWebAuthnRegistrar(webauthn.NewRegistrar(webauthnHelper)))
		logger.Info("self-service passkey registration enabled (/me/mfa/webauthn)")
	}
	if err := b.wireWebAuthnPrimaryAuth(webauthnHelper); err != nil {
		return err
	}
	return b.wireMFAProvider()
}

// wireWebAuthnPrimaryAuth opts into passwordless passkey PRIMARY login
// (cfg.WebAuthn.primary_auth_enabled): it registers a
// webauthn.WebAuthnPrimaryAuthenticator under provider="webauthn" in the
// SAME s.authenticators registry every other authenticator uses, sharing the
// helper already built above with the step-up MFA path + the standalone
// /webauthn/* ceremony routes. Default-off and purely additive: when the
// flag is false (or the WebAuthn subsystem itself is disabled, so helper is
// nil), /auth/login behaves byte-identically to a build without this
// feature — the existing password + WebAuthn-second-factor flow is
// untouched either way.
func (b *appBuilder) wireWebAuthnPrimaryAuth(webauthnHelper *webauthn.Helper) error {
	if webauthnHelper == nil || !b.cfg.WebAuthn.PrimaryAuthEnabled {
		return nil
	}
	primaryAuth, err := webauthn.NewWebAuthnPrimaryAuthenticator(webauthnHelper, webauthn.WithWebAuthnPrimaryLogger(b.logger))
	if err != nil {
		return fmt.Errorf("webauthn primary authenticator: %w", err)
	}
	b.opts = append(b.opts, sso.WithAuthenticator(primaryAuth))
	b.logger.Info("passwordless passkey primary login enabled (/auth/login provider=webauthn)")
	return nil
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
	b.mfaEnrollStore = store // retained for the GDPR eraser
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
	mfaProvider, mfaStore, mfaTTL, _, pushApprovalStore, pushNotify, err := serverbuildstore.BuildMFA(cfg.MFA, b.totpAuth, b.webauthnHelper, logger, b.redis)
	if err != nil {
		return fmt.Errorf("mfa: %w", err)
	}
	b.mfaChallengeStore = mfaStore
	b.mfaChallengeTTL = mfaTTL
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
// hot path) plus its SQLite readiness checks. threatExec is the Active ITDR
// executor from wireThreatAction (nil when threat_action is disabled).
func (b *appBuilder) wireAnomaly(threatExec threataction.ThreatExecutor) error {
	cfg, logger := b.cfg, b.logger
	anomalyRT, err := buildAnomaly(cfg.Anomaly, b.recorder, b.metricsRegistry, logger, threatExec)
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

// wireTrustScoring builds the Zero Trust Framework Phase 1 composite trust
// scorer (trust.enabled) and wires sso.WithTrustScorer. Called from
// wireGovernance, AFTER wireAnomaly has already populated b.anomalyRT (nil
// when anomaly.enabled=false), so the ip_reputation/behavior scorers can read
// the SAME anomaly stores the anomaly detectors populate — through the
// composition-root adapters in serverbuildplatform.BuildTrustScorer — rather
// than a second, disconnected data source. The score is ADVISORY-only: it is
// only consulted at /auth/login once access_policies.enforce is ALSO true
// (see docs/config-reference.md's "Trust Scoring" section). No-op
// (byte-identical build) when trust.enabled is false.
func (b *appBuilder) wireTrustScoring() error {
	cfg := b.cfg
	ipSalt, err := decodeAnomalySalt(cfg.Anomaly.IPSalt)
	if err != nil {
		return fmt.Errorf("trust: anomaly.ip_salt: %w", err)
	}
	var ipFailCounter anomaly.IPFailureCounter
	var recentStore anomaly.RecentLoginStore
	if b.anomalyRT != nil {
		ipFailCounter = b.anomalyRT.ipFailCounter
		recentStore = b.anomalyRT.recentStore
	}
	scorer, err := serverbuildplatform.BuildTrustScorer(cfg.Trust, ipFailCounter, recentStore, ipSalt, b.metricsRegistry)
	if err != nil {
		return fmt.Errorf("trust scoring: %w", err)
	}
	if scorer == nil {
		return nil
	}
	b.opts = append(b.opts, sso.WithTrustScorer(scorer))
	// trust.serialization is a sibling of trust.weights, not nested under
	// this scorer's own Enabled gate — but with neither sub-flag set there is
	// nothing to wire, so skip the Option entirely (byte-identical to a build
	// predating WithTrustScoreSerialization). config.TrustSerializationConfig
	// mirrors trust.SerializationConfig field-for-field (see its doc comment)
	// so the conversion is a direct type conversion, not a hand-copied literal
	// that could silently drop a field on the next addition.
	if cfg.Trust.Serialization.StampSessionMetadata || cfg.Trust.Serialization.IncludeTokenClaim {
		b.opts = append(b.opts, sso.WithTrustScoreSerialization(trust.SerializationConfig(cfg.Trust.Serialization)))
	}
	b.logger.Info("trust scoring enabled — composite advisory score computed at /auth/login",
		"scorers", len(cfg.Trust.Weights),
		"serialization_session_metadata", cfg.Trust.Serialization.StampSessionMetadata,
		"serialization_token_claim", cfg.Trust.Serialization.IncludeTokenClaim)
	return nil
}
