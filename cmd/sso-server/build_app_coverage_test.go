package main

import (
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/cmd/sso-server/serverassets"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/audit"
)

// shutdownApp tears down the lifecycle goroutines + closers a fully-featured
// buildApp spins up, mirroring run()'s cleanup so the kitchen-sink test leaves
// no leaked goroutines or open SQLite handles for -race to flag. Every
// channel wait is bounded by ctx (like run()) so a goroutine the test can't
// cleanly join never wedges the suite.
func shutdownApp(t *testing.T, a *app) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	waitBounded := func(done <-chan struct{}) {
		if done == nil {
			return
		}
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
	if a.auditRetentionCancel != nil {
		a.auditRetentionCancel()
		waitBounded(a.auditRetentionDone)
	}
	if a.snapshotRetentionCancel != nil {
		a.snapshotRetentionCancel()
		waitBounded(a.snapshotRetentionDone)
	}
	if a.pushPruneCancel != nil {
		a.pushPruneCancel()
		waitBounded(a.pushPruneDone)
	}
	if a.cibaPruneCancel != nil {
		a.cibaPruneCancel()
		waitBounded(a.cibaPruneDone)
	}
	if a.keyRotationCancel != nil {
		a.keyRotationCancel()
		waitBounded(a.keyRotationStop)
	}
	if a.credentialSchedCancel != nil {
		a.credentialSchedCancel()
		waitBounded(a.credentialSchedDone)
	}
	if a.configDriftCancel != nil {
		a.configDriftCancel()
		waitBounded(a.configDriftDone)
	}
	if a.breakGlassCancel != nil {
		a.breakGlassCancel()
		waitBounded(a.breakGlassDone)
	}
	if c, ok := a.configAuditStore.(io.Closer); ok {
		_ = c.Close()
	}
	if a.anomalyRT != nil {
		a.anomalyRT.close(ctx)
	}
	if a.auditAsyncSink != nil {
		_ = a.auditAsyncSink.Close(ctx)
	}
	if a.invalidationBus != nil {
		_ = a.invalidationBus.Close()
		waitBounded(a.busStop)
	}
	if a.signingKeyRegistry != nil {
		_ = a.signingKeyRegistry.Close()
		waitBounded(a.signingKeyStop)
	}
	if c, ok := a.connectionStore.(io.Closer); ok {
		_ = c.Close()
	}
	if a.tenantStore != nil {
		if c, ok := a.tenantStore.(io.Closer); ok {
			_ = c.Close()
		}
	}
	if a.registry != nil {
		_ = a.registry.Close()
	}
}

// -----------------------------------------------------------------------------
// buildApp + buildHTTPHandler + newGRPCServer — feature-rich wiring
// -----------------------------------------------------------------------------

// fullFeatureConfig turns on a broad cross-section of opt-in feature blocks so
// buildApp / buildHTTPHandler / newGRPCServer walk their conditional wiring
// branches in one pass: admin (+REST gateway), audit (memory + async + hash
// chain + API), permissions (+embed), network policy (+API), self-service
// (password + signup + data export + account erase + reset), MFA push callback,
// snapshot, releases, tenant, connections, cluster bus, geo, region, anomaly,
// SCIM groups, CIBA, password health.
func fullFeatureConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}

	cfg.Admin.Enabled = true
	cfg.Admin.APIRESTEnabled = true

	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 32
	cfg.Audit.APIEnabled = true
	cfg.Audit.HashChain = true
	cfg.Audit.Async.Enabled = true
	cfg.Audit.Async.BufferSize = 16
	cfg.Audit.Async.Workers = 2

	cfg.Events.Enabled = true
	cfg.Events.MaxSubscribers = 4
	cfg.Events.ReplayBuffer = 8
	cfg.Events.HeartbeatInterval = time.Hour

	cfg.Permissions.Enabled = true
	cfg.Permissions.EmbedInLogin = true

	cfg.Network.Enabled = true
	cfg.Network.Store = "memory"
	cfg.Network.APIEnabled = true
	cfg.Network.Policies = []config.NetworkPolicySeed{
		{Name: "intranet", CIDRs: []string{"10.0.0.0/8"}, Priority: 100},
	}

	cfg.SelfService.Password.Backend = "memory"
	cfg.SelfService.Signup = true
	cfg.SelfService.DataExport = true
	cfg.SelfService.AccountDeletion = true
	cfg.SelfService.PasswordReset.Backend = "memory"

	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "inline"
	cfg.Snapshot.RedactSecrets = true
	cfg.Snapshot.Retention.Enabled = true
	cfg.Snapshot.Retention.Keep = 10
	cfg.Snapshot.Retention.Interval = time.Hour

	// Scheduled signing-key rotation — the default EdDSA issuer ships a
	// StartRotation scheduler, so this walks the rotation-loop branch +
	// the OnRotate closure wiring. shutdownApp cancels the loop.
	cfg.Keys.Rotation.Enabled = true
	cfg.Keys.Rotation.Interval = 24 * time.Hour
	cfg.Keys.Rotation.GracePeriod = time.Hour

	cfg.Releases.Enabled = true
	cfg.Releases.Store.Backend = "memory"
	cfg.Releases.Pinner.Backend = "noop"

	cfg.Tenant.Enabled = true
	cfg.Tenant.Backend = "memory"
	cfg.Tenant.Tenants = []config.TenantSeedConfig{{ID: "t1", Slug: "t1", Name: "Tenant One"}}

	cfg.Connections = config.ConnectionsConfig{
		Enabled: true,
		Backend: "memory",
		Connections: []config.ConnectionSeedConfig{{
			ID: "c1", TenantID: "t1", Type: "oidc", DisplayName: "C1",
			Domains: []string{"c1.example.com"}, Enabled: true,
			Config: map[string]string{"oidc_issuer": "https://idp.c1.example.com"},
		}},
	}

	// NOTE: cluster.bus is intentionally left off — its subscriber goroutine
	// is owned by the Server's lifecycle (not the cmd app), so a test can't
	// cleanly join it. serverbuildplatform.BuildInvalidationBus has dedicated coverage in
	// cluster_bus_test.go.

	cfg.Geo.Enabled = true
	cfg.Geo.Static.Entries = []config.GeoStaticEntry{
		{CIDR: "10.0.0.0/8", CountryCode: "US", RecommendedLanguage: "en-US"},
	}

	cfg.Region.ServingRegion = "us-east-1"
	cfg.Region.AllowedRegions = []string{"us-east-1"}

	cfg.SCIM.Groups.Enabled = true
	cfg.SCIM.Groups.GroupClientID = "scim-groups"

	// OAuth grant stores (memory) — each block flips its buildApp branch.
	cfg.OAuth.AuthCode.Enabled = true
	cfg.OAuth.RefreshToken.Enabled = true
	cfg.OAuth.RefreshToken.RotationGraceWindow = 5 * time.Second
	cfg.OAuth.DeviceCode.Enabled = true
	cfg.OAuth.PAR.Enabled = true
	cfg.OAuth.JARM.Enabled = true

	// Server-level OIDC/security toggles.
	cfg.Server.SignedMetadata = true
	cfg.Server.OAuth21StrictMode = true
	cfg.Server.PairwiseSubjects.Enabled = true
	cfg.Server.PairwiseSubjects.Salt = "pairwise-deployment-salt"
	cfg.Server.DiscoveryCacheTTL = 5 * time.Second
	cfg.Server.DiscoveryDocCacheTTL = 5 * time.Second
	cfg.Server.JWKSCacheTTL = 5 * time.Minute
	cfg.Identity.ClientCache.Enabled = true

	cfg.BackchannelLogout.Enabled = true
	cfg.BackchannelLogout.Index.Backend = "memory"

	// CIBA on sqlite (+ prune loop + ping notifier) — exercises serverbuildstore.BuildCIBA,
	// the sqlite readycheck/schema branch, the prune scheduler, and the
	// ping-mode wiring. shutdownApp cancels the prune loop.
	cfg.CIBA.Enabled = true
	cfg.CIBA.Backend = "sqlite"
	cfg.CIBA.SQLiteDSN = "file:" + filepath.Join(t.TempDir(), "ciba.db") + "?_journal=WAL"
	cfg.CIBA.PruneInterval = time.Hour
	cfg.CIBA.Ping.Enabled = true
	cfg.CIBA.Ping.Endpoints = map[string]string{"client-1": "https://client-1.example.com/ciba"}

	// OIDC JWE response encryption (multi — both RSA + ECDH encrypters).
	cfg.OIDC.ResponseEncryption.Enabled = true
	cfg.OIDC.ResponseEncryption.Backend = "multi"

	// Dynamic client registration (RFC 7591/7592).
	cfg.ClientRegistration.Enabled = true
	cfg.ClientRegistration.AllowOpenRegistration = true

	// DPoP nonce + iat-window knobs.
	cfg.Security.DPoPNonce.Enabled = true
	cfg.DPoP.ProofMaxAge = 60 * time.Second
	cfg.DPoP.MaxClockSkew = 60 * time.Second

	// Rate limiting (memory), JTI replay (memory), account lockout (memory),
	// mTLS (tls backend) — all the security-layer buildApp branches.
	cfg.Security.RateLimit.Enabled = true
	cfg.Security.RateLimit.Backend = "memory"
	cfg.Security.RateLimit.DefaultPerSec = 50
	cfg.Security.RateLimit.DefaultBurst = 100
	cfg.Security.RateLimit.Prefixes = []config.RateLimitPrefixConfig{
		{Prefix: "/token", PerSec: 10, Burst: 20},
	}
	cfg.Security.JTIReplay.Enabled = true
	cfg.Security.JTIReplay.Backend = "memory"
	cfg.Security.AccountLockout.Enabled = true
	cfg.Security.AccountLockout.Backend = "memory"
	cfg.Security.AccountLockout.MaxFailures = 5
	cfg.Security.MTLS.Enabled = true // default tls backend (in-process)

	// Tenant suspension check (post-validation gate) branch.
	cfg.Tenant.SuspensionCheck.Enabled = true

	// Anomaly detection (memory) with one detector enabled.
	cfg.Anomaly.Enabled = true
	cfg.Anomaly.IPSalt = "0011223344556677"
	cfg.Anomaly.RecentLogin.Backend = "memory"
	cfg.Anomaly.IPFailure.Backend = "memory"
	cfg.Anomaly.Detectors.Velocity.Enabled = true
	cfg.Anomaly.Detectors.Velocity.HourlyLimit = 100

	// SPIFFE + CAEP receiver — JWKS-file-backed boot paths through buildApp.
	cfg.SPIFFE.Enabled = true
	cfg.SPIFFE.TrustDomain = "example.org"
	cfg.SPIFFE.Audience = "https://sso.example.com"
	cfg.SPIFFE.JWKSFile = writeJWKSFile(t, "https://spire.example.org")

	cfg.CAEP.Receiver.Enabled = true
	cfg.CAEP.Receiver.Audience = "https://sso.example.com"
	cfg.CAEP.Receiver.Transmitters = []config.CAEPTransmitterConfig{{
		Issuer:      "https://tx.example.com",
		JWKSFile:    writeJWKSFile(t, "https://tx.example.com"),
		SubjectMode: "opaque",
	}}

	// OpenID Federation 1.0 entity config — signed by the JWT issuer, no
	// extra trust setup. Exercises serverbuildplatform.BuildFederationConfig via buildApp.
	cfg.Federation.Enabled = true
	cfg.Federation.OrganizationName = "Kitchen Sink Org"

	// FAPI 2.0 compliance profile (inspection-only — audit, no reject).
	cfg.OAuth.Compliance.Profile = "fapi_2"
	cfg.OAuth.Compliance.InspectionOnly = true

	// MFA via push (sqlite backend, so a.pushApprovalStore is non-nil and
	// the reference approval callback route mounts) + a prune loop. The
	// sqlite handle also flows into the /readyz + storage-health sources.
	cfg.MFA.Enabled = true
	cfg.MFA.Provider.Kind = "push"
	cfg.MFA.Provider.Push.Backend = "sqlite"
	cfg.MFA.Provider.Push.SQLite.DSN = "file:" + filepath.Join(t.TempDir(), "push.db") + "?_journal=WAL"
	cfg.MFA.Provider.Push.PruneInterval = time.Hour
	cfg.MFA.Provider.Push.Callback.Enabled = true
	cfg.MFA.Provider.Push.Callback.BearerToken = "callback-secret"
	cfg.MFA.Challenge.Backend = "memory"

	// Envoy ext_authz HTTP seam.
	cfg.Mesh.ExtAuthz.Enabled = true

	// Discovery informational metadata + ACR advertisement.
	cfg.Server.SupportedACRValues = []string{"urn:mace:incommon:iap:silver"}
	cfg.Server.OperatorMetadata = config.OperatorMetadataConfig{
		PolicyURI: "https://sso.example.com/policy",
		TosURI:    "https://sso.example.com/tos",
	}

	// Body limit (+ per-prefix override), CORS, trusted proxies.
	cfg.Security.BodyLimit.MaxBytes = 1 << 20
	cfg.Security.BodyLimit.Overrides = []config.BodyLimitOverrideConfig{
		{Prefix: "/par", MaxBytes: 64 << 10},
	}
	cfg.Security.CORS.Enabled = true
	cfg.Security.CORS.AllowedOrigins = []string{"https://app.example.com"}
	cfg.Security.TrustedProxies.CIDRs = []string{"10.0.0.0/8"}
	cfg.Security.TrustedProxies.Hops = 1

	// Per-tenant metrics allowlist.
	cfg.Metrics.TenantLabelAllowlist = []string{"t1"}

	// Hosted login + self-service portal SPAs, consent gate, native SSO,
	// protected-resource metadata — the trailing buildApp opt-in blocks.
	cfg.HostedLogin.Enabled = true
	cfg.SelfService.Consent.Backend = "memory"
	cfg.NativeSSO.Backend = "memory"

	// WebAuthn ceremony — covers buildApp's webauthn build + buildHTTPHandler's
	// ceremony-route mount (the routes hang off the SSO router).
	cfg.WebAuthn.Enabled = true
	cfg.WebAuthn.RPID = "example.com"
	cfg.WebAuthn.RPDisplayName = "Example SSO"
	cfg.WebAuthn.RPOrigins = []string{"https://sso.example.com"}
	cfg.ProtectedResource.Enabled = true
	cfg.ProtectedResource.Resource = "https://api.example.com"
	cfg.ProtectedResource.AuthorizationServers = []string{"https://sso.example.com"}

	return cfg
}

// TestBuildApp_FullFeatureSet drives buildApp through a wide feature set,
// then exercises buildHTTPHandler (admin gateway + SCIM + compliance + push
// callback paths) and newGRPCServer (every conditional service registration).
// The goal is branch coverage of the cmd assembly layer, not behavior — the
// behavior is pinned by the dedicated per-feature tests.
func TestBuildApp_FullFeatureSet(t *testing.T) {
	t.Parallel()
	cfg := fullFeatureConfig(t)
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)

	if a.server == nil {
		t.Fatal("server nil")
	}
	if a.recorder == nil {
		t.Fatal("recorder nil with audit enabled")
	}
	if a.adminMW == nil {
		t.Fatal("adminMW nil with admin enabled")
	}
	if a.snapshotPipeline == nil || a.releaseStore == nil || a.tenantStore == nil {
		t.Fatal("snapshot/release/tenant subsystems not wired")
	}
	if a.server.SSEBroker() == nil {
		t.Fatal("SSE broker not wired with events.enabled")
	}
	// closeSSEBroker (called ahead of the HTTP graceful drain in run(); see
	// main_shutdown.go) must be safe to call on a live broker.
	closeSSEBroker(a)

	// buildHTTPHandler walks the admin gateway + SCIM + compliance branches.
	h, err := buildHTTPHandler(cfg, a, quietLogger())
	if err != nil {
		t.Fatalf("buildHTTPHandler: %v", err)
	}
	if h == nil {
		t.Fatal("nil handler")
	}

	// newGRPCServer registers every conditional admin service.
	gs, err := newGRPCServer(a, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if gs == nil {
		t.Fatal("nil grpc server")
	}
	gs.Stop()

	// Smoke the composed handler: an unauthenticated admin REST call is
	// gated (401), proving the admin middleware wraps the gateway.
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/admin/clients")
	if err != nil {
		t.Fatalf("GET admin clients: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("admin REST without bearer = %d; want 401", resp.StatusCode)
	}
}

// TestBuildApp_SignupRequiresPasswordStore — self-service signup without a
// password store is a misconfiguration that must fail at boot.
func TestBuildApp_SignupRequiresPasswordStore(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.SelfService.Signup = true
	// No SelfService.Password backend.
	if _, err := buildApp(cfg, quietLogger()); err == nil {
		t.Fatal("expected error: signup requires password store")
	}
}

// -----------------------------------------------------------------------------
// newGRPCServer — minimal app (no admin / no network)
// -----------------------------------------------------------------------------

// TestNewGRPCServer_MinimalRegistersCoreServices — even a bare app registers
// the always-on Phase A services without panicking.
func TestNewGRPCServer_MinimalRegistersCoreServices(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 8
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)
	gs, err := newGRPCServer(a, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if gs == nil {
		t.Fatal("nil grpc server")
	}
	gs.Stop()
}

// -----------------------------------------------------------------------------
// newSlogLogger + ContextLogger methods
// -----------------------------------------------------------------------------

func TestNewSlogLogger_LevelsAndMethods(t *testing.T) {
	t.Parallel()
	for _, lvl := range []string{"debug", "info", "error", "unknown-falls-back-to-info"} {
		l := newSlogLogger(lvl)
		if l == nil {
			t.Fatalf("newSlogLogger(%q) = nil", lvl)
		}
		// Exercise every method shape (no panic / nil-deref).
		l.Info("info", "k", "v")
		l.Error("error", "k", "v")
		l.Debug("debug", "k", "v")
		ctx := context.Background()
		l.InfoCtx(ctx, "info-ctx", "k", "v")
		l.ErrorCtx(ctx, "error-ctx", "k", "v")
		l.DebugCtx(ctx, "debug-ctx", "k", "v")
	}
}

// -----------------------------------------------------------------------------
// writeAdminPasswordFile
// -----------------------------------------------------------------------------

func TestWriteAdminPasswordFile_WritesMode0600(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "admin-password")
	if err := writeAdminPasswordFile(path, "s3cr3t"); err != nil {
		t.Fatalf("writeAdminPasswordFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o; want 600", perm)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "s3cr3t\n" {
		t.Errorf("contents = %q; want trailing-newline password", got)
	}
}

func TestWriteAdminPasswordFile_MissingDirErrors(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "no-such-dir", "admin-password")
	if err := writeAdminPasswordFile(path, "x"); err == nil {
		t.Fatal("expected error writing into a non-existent parent dir")
	}
}

// -----------------------------------------------------------------------------
// embedded-asset sub-filesystems
// -----------------------------------------------------------------------------

func TestAssetSubFS_RootIndexResolvable(t *testing.T) {
	t.Parallel()
	cases := map[string]fs.FS{
		"admin":  serverassets.AdminSubFS(),
		"login":  serverassets.LoginSubFS(),
		"portal": serverassets.PortalSubFS(),
	}
	for name, sub := range cases {
		if sub == nil {
			t.Errorf("%s sub-FS is nil", name)
			continue
		}
		// The embed contract guarantees an index.html at the rooted path.
		if _, err := fs.Stat(sub, "index.html"); err != nil {
			t.Errorf("%s sub-FS missing index.html: %v", name, err)
		}
	}
}

// -----------------------------------------------------------------------------
// recordCompliance — failure outcome + nil-recorder guard
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// callbackClientIP / normalizeIP — direct unit coverage of the XFF + RemoteAddr
// extraction branches the handler tests reach only indirectly.
// -----------------------------------------------------------------------------

func TestCallbackClientIP_XFFFirstHopWins(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/push/approval/x/approve", nil)
	r.RemoteAddr = "10.9.9.9:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	ip := callbackClientIP(r)
	if ip == nil || ip.String() != "203.0.113.7" {
		t.Fatalf("callbackClientIP = %v; want 203.0.113.7 (first XFF hop)", ip)
	}
}

func TestCallbackClientIP_FallsBackToRemoteAddr(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "198.51.100.4:5555"
	ip := callbackClientIP(r)
	if ip == nil || ip.String() != "198.51.100.4" {
		t.Fatalf("callbackClientIP = %v; want 198.51.100.4 from RemoteAddr", ip)
	}
}

func TestCallbackClientIP_RemoteAddrWithoutPort(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "192.0.2.9" // no port → SplitHostPort errs, host = whole string
	ip := callbackClientIP(r)
	if ip == nil || ip.String() != "192.0.2.9" {
		t.Fatalf("callbackClientIP = %v; want 192.0.2.9", ip)
	}
}

func TestCallbackClientIP_UnparseableReturnsNil(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "not-an-ip"
	if ip := callbackClientIP(r); ip != nil {
		t.Fatalf("callbackClientIP = %v; want nil for unparseable RemoteAddr", ip)
	}
}

func TestRecordCompliance_NilRecorderNoPanic(t *testing.T) {
	t.Parallel()
	// nil recorder is the disabled-audit path; must be a silent no-op.
	recordCompliance(nil, audit.EventAdminSubjectExported, "u1",
		httptest.NewRequest(http.MethodGet, "/", nil), nil)
}

func TestRecordCompliance_FailureOutcomeStampsReason(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(8)
	rec := audit.New(sink)
	opErr := context.DeadlineExceeded
	recordCompliance(rec, audit.EventAdminSubjectErased, "u1",
		httptest.NewRequest(http.MethodPost, "/", nil), opErr)

	events, err := sink.Query(context.Background(), audit.Query{Type: audit.EventAdminSubjectErased})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("recorded %d events; want 1", len(events))
	}
	e := events[0]
	if e.Outcome != audit.OutcomeFailure {
		t.Errorf("outcome = %q; want failure", e.Outcome)
	}
	if e.Reason == "" {
		t.Error("reason not stamped from opErr")
	}
}
