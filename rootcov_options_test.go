package sso_test

// rootcov_options_test.go covers the WithXxx option constructors in options.go,
// options_misc.go, options_passwd.go, and options_security.go. Each option is a
// closure mutating the Server, so building one server with the broadest set of
// options exercises all their bodies in a single NewServer call. Options that
// need a heavyweight collaborator (federation signer, SPIFFE JWKS source,
// metering aggregator) are intentionally omitted.

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/cors"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/fapi"
	"github.com/snaplink/sso/geo/static"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/netpolicy"
	netmem "github.com/snaplink/sso/netpolicy/memory"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ratelimit"
	"github.com/snaplink/sso/region"
	"github.com/snaplink/sso/spi"
)

// --- minimal stub collaborators for interface-typed options ---

type rcovLogoutTokenIssuer struct{}

func (rcovLogoutTokenIssuer) IssueLogoutToken(context.Context, *sso.LogoutTokenRequest) (string, error) {
	return "logout.token", nil
}

type rcovLogoutNotifier struct{}

func (rcovLogoutNotifier) Notify(context.Context, string, string) error { return nil }

type rcovMFAProvider struct{}

func (rcovMFAProvider) SupportedMethods() []string { return []string{"totp"} }
func (rcovMFAProvider) Verify(context.Context, string, string, map[string]string) error {
	return nil
}

// TestRcovOptions_KitchenSink applies the broadest practical option set and
// asserts the server constructs + the cheaply-observable options stuck.
func TestRcovOptions_KitchenSink(t *testing.T) {
	scorer, err := defaultimpl.NewRuleBasedRiskScorer(defaultimpl.RuleBasedRiskScorerConfig{})
	if err != nil {
		t.Fatalf("risk scorer: %v", err)
	}
	trustedProxies, err := sso.WithTrustedProxies([]string{"10.0.0.0/8"}, 1)
	if err != nil {
		t.Fatalf("WithTrustedProxies: %v", err)
	}

	netStore := netmem.New()
	classifier := netpolicy.NewClassifier()

	srv := sso.NewServer(
		// Core identity + issuer.
		sso.WithIssuer("https://opt.example.com"),
		sso.WithBaseURL("https://opt.example.com"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithSessionTTL(time.Hour),
		sso.WithTokenTTL(time.Minute),

		// Password / self-service surface.
		sso.WithPasswordCredentialStore(defaultimpl.NewMemoryPasswordCredentialStore()),
		sso.WithPasswordResetStore(defaultimpl.NewMemoryPasswordResetStore(), time.Hour),
		sso.WithPasswordResetResolver(func(context.Context, string) (string, error) {
			return "u", nil
		}),
		sso.WithPasswordResetDeliveryResolver(func(context.Context, string) (string, error) {
			return "user@example.com", nil
		}),
		sso.WithEmailChangeStore(defaultimpl.NewMemoryEmailChangeStore(), time.Hour),
		sso.WithSelfServiceSignup(),
		sso.WithSelfEditableProfileAttributes("nickname"),
		sso.WithMFAEnrollmentStore(defaultimpl.NewMemoryMFAEnrollmentStore()),
		sso.WithInvitationStore(defaultimpl.NewMemoryInvitationStore()),
		sso.WithJITMembership(),
		sso.WithTenantUserStore(defaultimpl.NewMemoryTenantUserStore()),

		// Security surface.
		sso.WithJTIReplayStore(defaultimpl.NewMemoryJTIReplayStore()),
		sso.WithJTIReplayFailClosed(),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithRefreshRotationGrace(time.Second),
		sso.WithSubjectClientIndex(defaultimpl.NewMemorySubjectClientIndex()),
		sso.WithMeshExtAuthz("/mesh/ext-authz"),
		sso.WithAuditAPI(),
		sso.WithTracingMiddleware(),
		sso.WithRequestIDMiddleware(),

		// Discovery / metadata.
		sso.WithOperatorMetadata("https://policy", "https://tos", "https://docs"),
		sso.WithSupportedACRValues("urn:acr:1"),
		sso.WithScopeDescriptions(map[string]string{"openid": "OpenID"}),
		sso.WithDiscoveryCacheTTL(5*time.Second),
		sso.WithDiscoveryDocCacheTTL(5*time.Second),
		sso.WithJWKSCacheTTL(time.Minute),

		// Grants.
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), time.Minute),
		sso.WithDeviceCodeStore(defaultimpl.NewMemoryDeviceCodeStore(), time.Minute, time.Second, "https://opt.example.com/device"),
		sso.WithPARStore(defaultimpl.NewMemoryPARStore(), time.Minute),
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{AllowOpenRegistration: true, DefaultActive: true}),
		sso.WithCIBA(defaultimpl.NewMemoryCIBAStore(), oauth.CIBATransportFunc(
			func(context.Context, string, string, map[string]string) error { return nil }), time.Minute, time.Second),
		sso.WithCIBAPingNotifier(oauth.CIBAPingNotifierFunc(
			func(context.Context, string, string, string) error { return nil })),

		// Backchannel logout.
		sso.WithBackchannelLogout(rcovLogoutTokenIssuer{}, rcovLogoutNotifier{}),
		sso.WithBackchannelLogoutMaxConcurrent(4),

		// Risk / MFA / anomaly.
		sso.WithRiskScorer(scorer),
		sso.WithMFAProvider(rcovMFAProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), time.Minute),

		// Permissions + network + geo + region.
		sso.WithPermissionProvider(permissions.NewMemoryProvider()),
		sso.WithEmbedPermissionsInLogin(),
		sso.WithNetworkPolicy(netStore, classifier),
		sso.WithNetworkPolicyAPI(),
		sso.WithGeoProvider(static.New()),
		sso.WithGeoMiddlewareOptions(sso.GeoMiddlewareOptions{}),
		sso.WithRegionMiddleware(region.ConfigPinnedResolver{Region: region.ID("us")}, region.MiddlewareOptions{}),

		// Observability / middleware.
		sso.WithMetrics(metrics.New()),
		sso.WithCORS(cors.Policy{AllowedOrigins: []string{"*"}}),
		sso.WithTracing("op"),
		sso.WithBodyLimit(1<<20),
		sso.WithBodyLimitForPath("/token", 1<<16),
		sso.WithRateLimit(ratelimit.Policy{}),
		sso.WithReadyCheck("rcov", func(context.Context) error { return nil }),
		sso.WithReadyCheckTimeout("rcov", time.Second),
		trustedProxies,

		// FAPI + OAuth 2.1.
		sso.WithFAPIProfile(fapi.ModeInspection),
		sso.WithOAuth21StrictMode(false),

		// Audit + tenant metrics.
		sso.WithAuditRecorder(audit.New(audit.NewMemorySink(10))),
		sso.WithTenantMetricsAllowlist([]string{"tenant-a"}),
		sso.WithCrossReplicaRevocation(),
	)

	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	// Spot-check a few options actually stuck via the public accessors.
	if srv.Issuer() != "https://opt.example.com" {
		t.Errorf("Issuer = %q", srv.Issuer())
	}
	if !srv.EmbedPermissions() {
		t.Error("EmbedPermissions not set")
	}
	if srv.Permissions() == nil {
		t.Error("Permissions provider not wired")
	}
	if srv.NetStore() == nil {
		t.Error("NetStore not wired")
	}
	if srv.Metrics() == nil {
		t.Error("Metrics not wired")
	}
	if !srv.TenantMetricsEnabled() {
		t.Error("TenantMetricsEnabled should be true with a non-empty allowlist")
	}
	if !srv.CrossReplicaRevocationEnabled() {
		t.Error("CrossReplicaRevocationEnabled not set")
	}
	// Building the handler must not panic with the full option set wired.
	if srv.Handler() == nil {
		t.Fatal("Handler() returned nil")
	}
}

// rcovUnusedSPI keeps the spi import referenced.
var _ = spi.DecisionAllow
