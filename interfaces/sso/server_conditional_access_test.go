package sso_test

// Drives the zero-trust conditional-access (CAP) advisory entry point, the
// read-only admin governance view, and the LIVE /auth/login Policy
// Enforcement Point end-to-end: the advisory method through the wired
// engine, GET /api/v1/admin/access-policies through the real AdminMiddleware
// (admin:read gate), and the live gate (enforceConditionalAccessLogin) driven
// through rcovNewServer + a real /auth/login round trip — deny, allow,
// require_step_up (both with and without an MFA path configured), the
// DeviceFingerprint + TrustScorer signal sources, and the store-outage
// fail-open contract.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/trust"
)

func denyLowTrustPolicy() conditionalaccess.Policy {
	return conditionalaccess.Policy{
		Name: "deny-low-trust", Priority: 100, Enabled: true,
		Conditions: conditionalaccess.Conditions{RiskScore: "> 0.5"},
		Actions:    conditionalaccess.Actions{Deny: true},
	}
}

func TestConditionalAccess_AdvisoryUnwired(t *testing.T) {
	t.Parallel()
	// A server without WithConditionalAccess returns a permissive allow so
	// callers can invoke the advisory method unconditionally.
	srv := sso.NewServer()
	d := srv.EvaluateConditionalAccess(context.Background(), sso.AccessContext{})
	if d.Verdict != conditionalaccess.VerdictAllow {
		t.Fatalf("unwired verdict = %q, want allow", d.Verdict)
	}
}

func TestConditionalAccess_AdvisoryWired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	if err := store.Put(ctx, denyLowTrustPolicy()); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	srv := sso.NewServer(sso.WithConditionalAccess(store, conditionalaccess.Config{}))

	// Low trust (0.1 -> risk 0.9) trips the deny policy.
	deny := srv.EvaluateConditionalAccess(ctx, sso.AccessContext{TrustScore: 0.1, TrustScoreKnown: true, DevicePosture: conditionalaccess.PostureManaged})
	if deny.Verdict != conditionalaccess.VerdictDeny || deny.MatchedPolicy != "deny-low-trust" {
		t.Fatalf("verdict %q matched %q, want deny/deny-low-trust", deny.Verdict, deny.MatchedPolicy)
	}
	// High trust (0.95 -> risk 0.05) does not match: default allow.
	allow := srv.EvaluateConditionalAccess(ctx, sso.AccessContext{TrustScore: 0.95, TrustScoreKnown: true, DevicePosture: conditionalaccess.PostureManaged})
	if allow.Verdict != conditionalaccess.VerdictAllow {
		t.Fatalf("high-trust verdict = %q, want allow", allow.Verdict)
	}
}

// capAdminEnv is an admin-gated httptest server with a wired CAP store.
type capAdminEnv struct {
	url   string
	token string
}

func capNewAdminServer(t *testing.T) *capAdminEnv {
	t.Helper()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, Name: "Admin Client",
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
	})

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, "", []string{"root"})
	_ = prov.AddRole(ctx, rcovClient, permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, rcovClient, []string{"root"})

	capStore := conditionalaccess.NewMemoryStore()
	policy := denyLowTrustPolicy()
	policy.DryRun = true
	_ = capStore.Put(ctx, policy)

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcovPasswordAuthAccepting()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithConditionalAccess(capStore, conditionalaccess.Config{Enforce: true}),
	)

	mw := sso.NewAdminMiddleware(srv, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("admin login status=%d body=%v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("no admin token: %v", out)
	}
	return &capAdminEnv{url: httpSrv.URL, token: token}
}

func TestConditionalAccess_AdminGate(t *testing.T) {
	t.Parallel()
	env := capNewAdminServer(t)
	path := env.url + "/api/v1/admin/access-policies"

	// No bearer => 401.
	if status, _ := rcovDo(t, http.MethodGet, path, "", nil); status != http.StatusUnauthorized {
		t.Errorf("no-bearer = %d, want 401", status)
	}
	// Garbage bearer => 401.
	if status, _ := rcovDo(t, http.MethodGet, path, "garbage", nil); status != http.StatusUnauthorized {
		t.Errorf("bad-bearer = %d, want 401", status)
	}
	// Valid admin bearer => 200 with the policy listed.
	status, out := rcovDo(t, http.MethodGet, path, env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("admin list = %d body=%v", status, out)
	}
	policies, _ := out["policies"].([]any)
	if len(policies) != 1 {
		t.Fatalf("policies = %d, want 1 (body=%v)", len(policies), out)
	}
	total, _ := out["total"].(float64)
	if int(total) != 1 {
		t.Errorf("total = %v, want 1", out["total"])
	}
	status, out = rcovDo(t, http.MethodPost, env.url+"/api/v1/admin/access-policies/converge", env.token, nil)
	if status != http.StatusOK || out["scanned"] == nil {
		t.Fatalf("admin converge = %d body=%v", status, out)
	}
}

// --- Live /auth/login PEP wiring (enforceConditionalAccessLogin) ---

// capLoginBody is the standard rcovNewServer password-login request body.
func capLoginBody() map[string]any {
	return map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	}
}

func stepUpAllPolicy() conditionalaccess.Policy {
	return conditionalaccess.Policy{
		Name: "stepup-all", Priority: 100, Enabled: true,
		Actions: conditionalaccess.Actions{RequireStepUp: "mfa", RestrictScopes: []string{"openid"}},
	}
}

func denyAllPolicy() conditionalaccess.Policy {
	return conditionalaccess.Policy{
		Name: "deny-all", Priority: 100, Enabled: true,
		Actions: conditionalaccess.Actions{Deny: true},
	}
}

func restrictScopesAllPolicy() conditionalaccess.Policy {
	return conditionalaccess.Policy{
		Name: "restrict-scopes-all", Priority: 100, Enabled: true,
		Actions: conditionalaccess.Actions{RestrictScopes: []string{"openid"}, Log: true},
	}
}

// errCAPStore is a Store whose List always fails — a real (not mocked) second
// Store implementation used to deterministically exercise the outage/fail-open
// path, same pattern as domains/conditionalaccess/evaluate_test.go's errStore.
type errCAPStore struct{}

func (errCAPStore) List(context.Context) ([]conditionalaccess.Policy, error) {
	return nil, errors.New("boom: policy store unreachable")
}
func (errCAPStore) Get(context.Context, string) (conditionalaccess.Policy, bool, error) {
	return conditionalaccess.Policy{}, false, nil
}
func (errCAPStore) Put(context.Context, conditionalaccess.Policy) error { return nil }
func (errCAPStore) Delete(context.Context, string) error                { return nil }

// TestConditionalAccess_EnforceOffLoginSucceeds proves a wired-but-not-enforced
// engine (Config.Enforce left false, the default) never touches the live
// /auth/login decision, even with a policy that would deny everything.
func TestConditionalAccess_EnforceOffLoginSucceeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	if err := store.Put(ctx, denyAllPolicy()); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	s := rcovNewServer(t, sso.WithConditionalAccess(store, conditionalaccess.Config{}))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
	if status != http.StatusOK {
		t.Fatalf("enforce-off login status=%d body=%v, want 200 (advisory-only must not block)", status, out)
	}
	if out["access_token"] == nil || out["access_token"] == "" {
		t.Errorf("no access_token: %v", out)
	}
}

// TestConditionalAccess_EnforceDeniesLogin proves Config.Enforce turns a
// matched VerdictDeny into a real 403 on /auth/login, using the degraded-trust
// floor (no TrustScorer wired -> TrustScoreKnown=false -> risk = 1-floor = 0.7)
// to trip the deny-low-trust policy's "risk_score > 0.5" condition.
func TestConditionalAccess_EnforceDeniesLogin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	if err := store.Put(ctx, denyLowTrustPolicy()); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	s := rcovNewServer(t, sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
	if status != http.StatusForbidden {
		t.Fatalf("enforced deny status=%d body=%v, want 403", status, out)
	}
	if out["error"] != "conditional_access_denied" {
		t.Errorf("error = %v, want conditional_access_denied", out["error"])
	}
}

// TestConditionalAccess_EnforceAllowsWhenNoPolicyMatches proves an enforced
// engine with no matching policy proceeds to mint tokens exactly like the
// unwired case (default-allow verdict).
func TestConditionalAccess_EnforceAllowsWhenNoPolicyMatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	// Never matches: risk (1 - trust) can never exceed 1.
	unreachable := conditionalaccess.Policy{
		Name: "unreachable", Priority: 100, Enabled: true,
		Conditions: conditionalaccess.Conditions{RiskScore: "> 1"},
		Actions:    conditionalaccess.Actions{Deny: true},
	}
	if err := store.Put(ctx, unreachable); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	s := rcovNewServer(t, sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
	if status != http.StatusOK {
		t.Fatalf("no-match status=%d body=%v, want 200", status, out)
	}
}

func TestConditionalAccess_EnforceRestrictsIssuedScopes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	if err := store.Put(ctx, restrictScopesAllPolicy()); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	s := rcovNewServer(t, sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))
	body := capLoginBody()
	body["scope"] = []string{"openid", "profile", "email"}

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", body)
	if status != http.StatusOK {
		t.Fatalf("restricted-scope status=%d body=%v", status, out)
	}
	if out["scope"] != "openid" {
		t.Errorf("scope=%v, want openid", out["scope"])
	}
}

// TestConditionalAccess_EnforceStepUpRoutesToMFA proves VerdictRequireStepUp
// routes through the EXISTING MFA orchestration (WithMFAProvider +
// WithMFAChallengeStore) rather than inventing a parallel mechanism.
func TestConditionalAccess_EnforceStepUpRoutesToMFA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	if err := store.Put(ctx, stepUpAllPolicy()); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	s := rcovNewServer(t,
		sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}),
		sso.WithMFAProvider(rcovTOTPProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 0),
	)

	body := capLoginBody()
	body["scope"] = []string{"openid", "profile"}
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", body)
	if status != http.StatusOK {
		t.Fatalf("step-up leg1 status=%d body=%v", status, out)
	}
	if out["error"] != "mfa_required" {
		t.Fatalf("expected mfa_required, got %v", out)
	}
	if out["mfa_challenge_id"] == "" || out["mfa_challenge_id"] == nil {
		t.Fatalf("no mfa_challenge_id: %v", out)
	}
	challengeID, _ := out["mfa_challenge_id"].(string)
	status, out = rcovPostJSON(t, s.http.URL+"/auth/mfa", "", map[string]any{
		"mfa_challenge_id": challengeID,
		"mfa_method":       "totp",
		"code":             "123456",
	})
	if status != http.StatusOK || out["scope"] != "openid" {
		t.Fatalf("step-up restricted result status=%d body=%v, want scope openid", status, out)
	}
}

// TestConditionalAccess_EnforceStepUpFailsClosedWithoutMFA proves a resolved
// operator authorization policy cannot be bypassed by incomplete deployment
// wiring. Store/signal outages still fail open in the separate test below.
func TestConditionalAccess_EnforceStepUpFailsClosedWithoutMFA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	if err := store.Put(ctx, stepUpAllPolicy()); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	s := rcovNewServer(t, sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
	if status != http.StatusForbidden {
		t.Fatalf("step-up-without-mfa status=%d body=%v, want 403", status, out)
	}
	if out["error"] != "conditional_access_denied" {
		t.Errorf("error=%v, want conditional_access_denied", out["error"])
	}
	if out["access_token"] != nil {
		t.Errorf("unexpected access_token: %v", out)
	}
}

// TestConditionalAccess_EnforceFailsOpenOnStoreOutage proves the live gate
// fails OPEN on a policy-store error — regardless of Config.DefaultDeny —
// because a trust/policy signal source must never become an account-lockout
// oracle an attacker can trip by starving it (AGENTS.md "Fail Modes").
func TestConditionalAccess_EnforceFailsOpenOnStoreOutage(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithConditionalAccess(errCAPStore{}, conditionalaccess.Config{Enforce: true, DefaultDeny: true}))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
	if status != http.StatusOK {
		t.Fatalf("store-outage status=%d body=%v, want 200 (fail open)", status, out)
	}
	if out["access_token"] == nil || out["access_token"] == "" {
		t.Errorf("no access_token: %v", out)
	}
}

// capBoolPtr is a tiny address-of helper for Conditions.DeviceManaged (a
// tri-state *bool: nil=unconstrained).
func capBoolPtr(b bool) *bool { return &b }

// TestConditionalAccess_DeviceFingerprintFeedsPosture proves a wired
// DeviceFingerprint's Lookup result reaches AccessContext.DevicePosture: a
// policy denying unmanaged devices lets a device Recorded as PostureManaged
// through, but still denies one that never reported a fingerprint (the
// engine's own conservative "unreported = not managed" default).
func TestConditionalAccess_DeviceFingerprintFeedsPosture(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	denyUnmanaged := conditionalaccess.Policy{
		Name: "deny-unmanaged", Priority: 100, Enabled: true,
		Conditions: conditionalaccess.Conditions{DeviceManaged: capBoolPtr(false)},
		Actions:    conditionalaccess.Actions{Deny: true},
	}
	if err := store.Put(ctx, denyUnmanaged); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	fp := conditionalaccess.NewMemoryDeviceFingerprint()
	if err := fp.Record(ctx, "known-device", conditionalaccess.PostureManaged); err != nil {
		t.Fatalf("record: %v", err)
	}
	s := rcovNewServer(t,
		sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}),
		sso.WithDeviceFingerprint(fp),
	)

	// No fingerprint header at all -> PostureUnknown -> DeviceManaged=false matches -> deny.
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
	if status != http.StatusForbidden {
		t.Fatalf("unreported device status=%d body=%v, want 403", status, out)
	}

	// The known, Managed fingerprint -> DeviceManaged=false does NOT match -> allow.
	status, out = capPostJSONWithHeader(t, s.http.URL+"/auth/login", core.HeaderDeviceID, "known-device", capLoginBody())
	if status != http.StatusOK {
		t.Fatalf("managed device status=%d body=%v, want 200", status, out)
	}

	// An UNRECORDED fingerprint -> lookup miss -> PostureUnknown -> deny, same
	// as no header at all (a lookup miss is never a free pass).
	status, out = capPostJSONWithHeader(t, s.http.URL+"/auth/login", core.HeaderDeviceID, "never-seen-device", capLoginBody())
	if status != http.StatusForbidden {
		t.Fatalf("unrecorded device status=%d body=%v, want 403", status, out)
	}
}

// capFailingTrustScorer always errors — proves a TrustScorer outage degrades
// to "unknown" (the engine's own conservative floor) rather than aborting the
// login or being treated as a deny signal itself.
type capFailingTrustScorer struct{}

func (capFailingTrustScorer) Name() string { return "failing" }
func (capFailingTrustScorer) Score(context.Context, trust.TrustSignals) (trust.TrustScore, error) {
	return trust.TrustScore{}, errors.New("boom: trust data source unreachable")
}

// capFixedTrustScorer always returns Value.
type capFixedTrustScorer struct{ value float64 }

func (capFixedTrustScorer) Name() string { return "fixed" }
func (s capFixedTrustScorer) Score(context.Context, trust.TrustSignals) (trust.TrustScore, error) {
	return trust.TrustScore{Value: s.value}, nil
}

// TestConditionalAccess_TrustScorerFeedsScore proves the wired TrustScorer's
// Value reaches the engine (high trust never trips the deny-low-trust policy;
// low trust does), and that a SCORER ERROR degrades to the engine's own floor
// rather than short-circuiting the login.
func TestConditionalAccess_TrustScorerFeedsScore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	newStore := func(t *testing.T) conditionalaccess.Store {
		t.Helper()
		store := conditionalaccess.NewMemoryStore()
		if err := store.Put(ctx, denyLowTrustPolicy()); err != nil {
			t.Fatalf("put policy: %v", err)
		}
		return store
	}

	t.Run("high_trust_allows", func(t *testing.T) {
		t.Parallel()
		// Also wire + present a KNOWN (Managed) device fingerprint: the engine
		// separately caps effective trust at the degraded floor whenever
		// DevicePosture is Unknown (see degradeTrust), so a high trust SCORE
		// alone isn't enough to prove the score reaches the engine — an
		// unreported device would cap it right back down regardless of value.
		fp := conditionalaccess.NewMemoryDeviceFingerprint()
		if err := fp.Record(ctx, "known-device", conditionalaccess.PostureManaged); err != nil {
			t.Fatalf("record: %v", err)
		}
		s := rcovNewServer(t,
			sso.WithConditionalAccess(newStore(t), conditionalaccess.Config{Enforce: true}),
			sso.WithTrustScorer(capFixedTrustScorer{value: 0.95}),
			sso.WithDeviceFingerprint(fp),
		)
		status, out := capPostJSONWithHeader(t, s.http.URL+"/auth/login", core.HeaderDeviceID, "known-device", capLoginBody())
		if status != http.StatusOK {
			t.Fatalf("high-trust status=%d body=%v, want 200", status, out)
		}
	})

	t.Run("low_trust_denies", func(t *testing.T) {
		t.Parallel()
		s := rcovNewServer(t,
			sso.WithConditionalAccess(newStore(t), conditionalaccess.Config{Enforce: true}),
			sso.WithTrustScorer(capFixedTrustScorer{value: 0.05}),
		)
		status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
		if status != http.StatusForbidden {
			t.Fatalf("low-trust status=%d body=%v, want 403", status, out)
		}
	})

	t.Run("scorer_error_degrades_not_aborts", func(t *testing.T) {
		t.Parallel()
		s := rcovNewServer(t,
			sso.WithConditionalAccess(newStore(t), conditionalaccess.Config{Enforce: true}),
			sso.WithTrustScorer(capFailingTrustScorer{}),
		)
		// Degraded floor (0.3) -> risk 0.7 -> trips ">0.5" -> deny. The point of
		// this test is that the scorer's ERROR itself never surfaces as a 5xx /
		// hang; it deterministically degrades to the engine's floor.
		status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
		if status != http.StatusForbidden {
			t.Fatalf("degraded-floor status=%d body=%v, want 403 (floor risk trips the policy)", status, out)
		}
	})
}

// capPostJSONWithHeader is rcovPostJSON plus one caller-supplied header (for
// the device-fingerprint header rcovPostJSON's fixed signature can't carry).
func capPostJSONWithHeader(t *testing.T, url, header, value string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(header, value)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body2, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := map[string]any{}
	if len(bytes.TrimSpace(body2)) > 0 {
		_ = json.Unmarshal(body2, &out)
	}
	return resp.StatusCode, out
}
