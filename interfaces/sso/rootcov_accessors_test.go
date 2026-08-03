package sso_test

// rootcov_accessors_test.go covers the generated Server field accessors in
// accessors.go. These exist so the hexagonal oauth/ + oidc/ handler packages
// can read Server config without reaching unexported fields; each is a tiny
// getter, so calling every one on a wired server is the cheapest way to cover
// the file. Side-effecting accessors are driven with a minimal HandlerContext.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/security"
)

// rcovCtx is a minimal HandlerContext for exercising ctx-taking accessors and
// helpers without standing up the full router. JSON / Redirect record the last
// call so a test could assert on them.
type rcovCtx struct {
	r      *http.Request
	w      *httptest.ResponseRecorder
	params map[string]string
	query  map[string]string
	store  map[string]any
	code   int
	body   any
}

func rcovNewCtx(method, url string) *rcovCtx {
	return &rcovCtx{
		r:      httptest.NewRequest(method, url, nil),
		w:      httptest.NewRecorder(),
		params: map[string]string{},
		query:  map[string]string{},
		store:  map[string]any{},
	}
}

func (c *rcovCtx) Request() *http.Request                { return c.r }
func (c *rcovCtx) ResponseWriter() http.ResponseWriter   { return c.w }
func (c *rcovCtx) Param(k string) string                 { return c.params[k] }
func (c *rcovCtx) Query(k string) string                 { return c.query[k] }
func (c *rcovCtx) Bind(any) error                        { return errors.New("no body") }
func (c *rcovCtx) JSON(code int, v any)                  { c.code = code; c.body = v }
func (c *rcovCtx) Redirect(code int, _ string)           { c.code = code }
func (c *rcovCtx) Set(k string, v any)                   { c.store[k] = v }
func (c *rcovCtx) Get(k string) any                      { return c.store[k] }
func (c *rcovCtx) Abort()                                {}
func (c *rcovCtx) Aborted() bool                         { return false }
func (c *rcovCtx) Written() bool                         { return false }
func (c *rcovCtx) SetResponseWriter(http.ResponseWriter) {}

// rcovWiredServer builds a *sso.Server with as many concerns wired to real
// Memory* impls as a single struct can hold, so the accessors return non-nil.
func rcovWiredServer(t *testing.T) *sso.Server {
	t.Helper()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	return sso.NewServer(
		sso.WithIssuer("https://accessor.example.com"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithDeviceCodeStore(defaultimpl.NewMemoryDeviceCodeStore(), 5*time.Minute, 5*time.Second, "https://accessor.example.com/device"),
		sso.WithPARStore(defaultimpl.NewMemoryPARStore(), time.Minute),
		sso.WithJTIReplayStore(defaultimpl.NewMemoryJTIReplayStore()),
		sso.WithSubjectClientIndex(defaultimpl.NewMemorySubjectClientIndex()),
		sso.WithConsentStore(defaultimpl.NewMemoryConsentStore()),
		sso.WithConnectionStore(connections.NewMemoryStore()),
		sso.WithTenantUserStore(defaultimpl.NewMemoryTenantUserStore()),
		sso.WithDeviceSecretStore(defaultimpl.NewMemoryDeviceSecretStore(), time.Hour),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), time.Minute),
		sso.WithMFAEnrollmentStore(defaultimpl.NewMemoryMFAEnrollmentStore()),
		sso.WithPasswordCredentialStore(defaultimpl.NewMemoryPasswordCredentialStore()),
		sso.WithAuditRecorder(audit.New(audit.NewMemorySink(10))),
		sso.WithOperatorMetadata("https://policy", "https://tos", "https://docs"),
		sso.WithSupportedACRValues("urn:acr:1"),
		sso.WithScopeDescriptions(map[string]string{"openid": "OpenID"}),
		sso.WithEmbedPermissionsInLogin(),
		sso.WithOAuth21StrictMode(true),
		sso.WithJTIReplayFailClosed(),
		sso.WithCrossReplicaRevocation(),
		sso.WithDiscoveryCacheTTL(5*time.Second),
		sso.WithDiscoveryDocCacheTTL(5*time.Second),
		sso.WithJWKSCacheTTL(5*time.Minute),
	)
}

// TestRcovAccessors_Getters calls every pure getter once. The assertions are
// light (these are config readbacks); the point is to execute the statements.
func TestRcovAccessors_Getters(t *testing.T) {
	t.Parallel()
	s := rcovWiredServer(t)

	if s.AuthCodeStore() == nil {
		t.Error("AuthCodeStore nil")
	}
	if s.RefreshTokenStore() == nil {
		t.Error("RefreshTokenStore nil")
	}
	if s.DeviceCodeStore() == nil {
		t.Error("DeviceCodeStore nil")
	}
	if s.PARStore() == nil {
		t.Error("PARStore nil")
	}
	if s.JTIReplayStore() == nil {
		t.Error("JTIReplayStore nil")
	}
	if s.SubjectClientIndex() == nil {
		t.Error("SubjectClientIndex nil")
	}
	if s.ConnectionStore() == nil {
		t.Error("ConnectionStore nil")
	}
	if s.ConsentStore() == nil {
		t.Error("ConsentStore nil")
	}
	if s.TenantUserStore() == nil {
		t.Error("TenantUserStore nil")
	}
	if s.DeviceSecretStore() == nil {
		t.Error("DeviceSecretStore nil")
	}
	if s.MFAChallengeStore() == nil {
		t.Error("MFAChallengeStore nil")
	}
	if s.Auditor() == nil {
		t.Error("Auditor nil")
	}
	if s.SessionMgr() == nil {
		t.Error("SessionMgr nil")
	}
	if s.ClientStoreAccessor() == nil {
		t.Error("ClientStoreAccessor nil")
	}
	if s.UserProviderAccessor() == nil {
		t.Error("UserProviderAccessor nil")
	}
	if len(s.TokenIssuers()) == 0 {
		t.Error("TokenIssuers empty")
	}
	if s.Issuer() != "https://accessor.example.com" {
		t.Errorf("Issuer = %q", s.Issuer())
	}
	if s.SrvLogger() == nil {
		t.Error("SrvLogger nil")
	}

	// TTL / duration getters — just execute them.
	_ = s.AuthCodeTTL()
	_ = s.RefreshTokenTTL()
	_ = s.DeviceCodeTTL()
	_ = s.DeviceCodeInterval()
	_ = s.DeviceVerifyBaseURL()
	_ = s.PARTTL()
	_ = s.CIBAStore()
	_ = s.CIBAUserCodeVerifier()
	_ = s.CIBARequestTTL()
	_ = s.CIBAPollInterval()
	_ = s.DCRPolicy()
	_ = s.MFAChallengeTTL()
	_ = s.JWKSCacheTTL()
	_ = s.JWKSCacheMaxAge()
	_ = s.DiscoveryCacheTTL()
	_ = s.DiscoveryDocCacheTTL()

	// Optional concerns that are nil here — still executes the getter body.
	_ = s.JARFetcher()
	_ = s.JARDecrypter()
	_ = s.JWEResponseEncrypter()
	_ = s.AccountLockout()
	_ = s.PairwiseStore()
	_ = s.ClientCertExtractor()
	_ = s.DPoPNonceProvider()
	_ = s.IDTokenIssuer()
	_ = s.MetadataSigner()
	_ = s.JARMSigner()
	_ = s.MFAProvider()
	_ = s.AnomalyRunner()
	_ = s.NetStore()
	_ = s.NetClassifier()
	_ = s.Metrics()
	_ = s.LogoutTokenIssuer()
	_ = s.LogoutNotifier()
	_ = s.FederationSigner()
	_ = s.FederationConfig()
	_ = s.FederationCache()
	_ = s.FederationFetchCache()
	// FederationEntityConfig() is intentionally NOT called: it dereferences the
	// federation entity handler, which is nil unless WithFederationEntity is
	// wired (a heavyweight signer setup out of scope here).
	_ = s.FederationNow()
	_ = s.StorageHealthSources()
	_ = s.Permissions()
	_ = s.InvalidationBus()

	// Boolean / scalar config readbacks.
	if !s.EmbedPermissions() {
		t.Error("EmbedPermissions should be true")
	}
	if !s.OAuth21Strict() {
		t.Error("OAuth21Strict should be true")
	}
	if !s.JTIReplayFailClosed() {
		t.Error("JTIReplayFailClosed should be true")
	}
	if !s.CrossReplicaRevocationEnabled() {
		t.Error("CrossReplicaRevocationEnabled should be true")
	}
	_ = s.AllowDynamicClientRegistration()
	if s.OpPolicyURI() != "https://policy" {
		t.Errorf("OpPolicyURI = %q", s.OpPolicyURI())
	}
	_ = s.OpTosURI()
	_ = s.ServiceDocumentation()
	if len(s.SupportedACRValues()) == 0 {
		t.Error("SupportedACRValues empty")
	}
	if len(s.ScopeDescriptions()) == 0 {
		t.Error("ScopeDescriptions empty")
	}
	_ = s.TenantMetricsEnabled()
	_ = s.TenantMetricsAllowlist()
}

// TestRcovAccessors_CtxHelpers drives the accessors that take a HandlerContext
// or perform a side effect.
func TestRcovAccessors_CtxHelpers(t *testing.T) {
	t.Parallel()
	s := rcovWiredServer(t)
	ctx := rcovNewCtx(http.MethodGet, "https://accessor.example.com/x")

	// Issuer resolution: explicit WithIssuer wins over the request base URL.
	if got := s.ResolveIssuer(ctx); got != "https://accessor.example.com" {
		t.Errorf("ResolveIssuer = %q", got)
	}
	_ = s.RequestBaseURL(ctx)
	if len(s.SigningAlgValues(context.Background())) == 0 {
		t.Error("SigningAlgValues empty")
	}

	// Error-body builders return a stable shape with the iss stamped.
	eb := s.AuthzErrorBody(ctx, "invalid_request")
	if eb["error"] != "invalid_request" {
		t.Errorf("AuthzErrorBody = %v", eb)
	}
	ebd := s.AuthzErrorBodyDesc(ctx, "invalid_request", "bad")
	if ebd["error_description"] != "bad" {
		t.Errorf("AuthzErrorBodyDesc = %v", ebd)
	}

	// Side-effecting helpers — exercise without asserting wire shape.
	s.SetBearerChallenge(ctx, "realm", "invalid_token", "nope")
	s.AuditPartialRevokeFailure(ctx, []string{"jwt"}, []string{"other"})
	s.RecordLogout(ctx, "sess-1", []string{"token"})
	s.RecordLoginSuccess(ctx, "client", "password", "jwt", "user", "sess")
	s.LogError("test error", "k", "v")

	// Frontchannel logout iframe gathering for an unknown subject is a no-op
	// list, then the renderer writes the wrapper page.
	iframes := s.GatherFrontchannelLogoutIframes(ctx, "subject", nil, "sid")
	s.RenderFrontchannelLogout(ctx, iframes, "")

	// AddReadyCheck registers a probe (no panic, idempotent enough for a test).
	s.AddReadyCheck("rcov-check", func(context.Context) error { return nil })

	// Tenant-metrics helpers are no-ops without an allowlist but still execute.
	s.RecordTenantLoginAttempt(ctx, "client", "success")
	s.RecordTenantTokenIssued(ctx, "client", "jwt")
	_ = s.TenantLabel(ctx, "client")

	// ID-token encryption: no encrypter wired, so it returns the signed token
	// unchanged. Just exercise the accessor body.
	_, _ = s.EncryptIDTokenForClient(context.Background(), &sso.Client{ID: "c"}, "signed.jwt")

	// BuildHandlerDeps assembles the hexagonal ServerDeps view; must be non-nil.
	if s.BuildHandlerDeps() == nil {
		t.Error("BuildHandlerDeps nil")
	}
}

// TestRcovAccessors_TokenAndClientHelpers covers the validate / client helpers.
func TestRcovAccessors_TokenAndClientHelpers(t *testing.T) {
	t.Parallel()
	s := rcovWiredServer(t)
	ctx := rcovNewCtx(http.MethodPost, "https://accessor.example.com/token")

	// A garbage token fails validation across all issuers (oracle-safe).
	if _, _, err := s.ValidateAnyToken(context.Background(), "not-a-token"); err == nil {
		t.Error("ValidateAnyToken on garbage should error")
	}
	// RevokeAcrossIssuers on a garbage token revokes nothing, fails nothing fatal.
	revoked, _ := s.RevokeAcrossIssuers(context.Background(), "not-a-token")
	if len(revoked) != 0 {
		t.Errorf("RevokeAcrossIssuers garbage revoked = %v", revoked)
	}
	// RequireClientStore succeeds (store wired).
	if err := s.RequireClientStore(); err != nil {
		t.Errorf("RequireClientStore = %v", err)
	}
	// AuthenticateClientCreds for an unknown client => invalid_client.
	if err := s.AuthenticateClientCreds(ctx, "no-client", "secret"); err == nil {
		t.Error("AuthenticateClientCreds unknown should error")
	}
	// ResolveLocalSubject is identity when no pairwise store is wired.
	got, err := s.ResolveLocalSubject(context.Background(), "subject-x")
	if err != nil || got != "subject-x" {
		t.Errorf("ResolveLocalSubject = %q, %v", got, err)
	}

	// Per-client issuer resolution falls back to the default strategy.
	client := &sso.Client{ID: "c1", TokenStrategy: "jwt"}
	if _, ti, err := s.IssuerForClient(client); err != nil || ti == nil {
		t.Errorf("IssuerForClient = %v, %v", ti, err)
	}
	_, _, _ = s.IDTokenIssuerForClient(client)
	_, _ = s.JARMSignerForClient(client)

	// JWT client-assertion verification on garbage input errors.
	if _, err := s.VerifyJWTClientAssertion(context.Background(), "garbage", "c1", s.Issuer()); err == nil {
		t.Error("VerifyJWTClientAssertion garbage should error")
	}

	// JWKS body cache: a compute func is invoked through the single-flight cache.
	called := 0
	body, err := s.ComputeJWKSDocument(func() ([]byte, error) {
		called++
		return []byte(`{"keys":[]}`), nil
	})
	if err != nil || string(body) != `{"keys":[]}` {
		t.Errorf("ComputeJWKSDocument = %q, %v", body, err)
	}
	s.InvalidateJWKSBodyCache()
}

// rcovUnusedImports keeps the security + oauth imports referenced even if a
// future edit drops their only direct use.
var (
	_ = security.AsymmetricJWSAlgs()
	_ = oauth.PathRegister
)
