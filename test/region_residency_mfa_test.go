package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/region"
	tenantmemory "github.com/snaplink/sso/domains/tenant/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/spi"
)

// The /auth/mfa second leg mints tokens NOW (finishLogin), from the serving
// region of THIS request. The residency gate that ran on the FIRST /auth/login
// leg can't speak for the region the mint actually happens in, so the second
// leg carries its own gate. This proves it: the challenge is issued from the
// home region (first leg passes), but the /auth/mfa completion arrives from a
// DISALLOWED region and is blocked before any token is minted.

// buildMFAResidencyHarness mirrors buildMFAHarness but binds the client to a
// constrained tenant and resolves the serving region from X-Serving-Region
// (Default = home eu-west-1). The first leg (no header) resolves to the home
// region so the residency gate lets the challenge issue; the second leg sets
// the header to pin the mint's region. Reuses mfa_test.go's totpStubStore /
// validTOTPCode / completeMFA helpers (same package).
func buildMFAResidencyHarness(t *testing.T) (*httptest.Server, []byte) {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("mfa-residency-test"))
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    "mfa-app",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
		TenantID:              residencyTenantID,
	})

	pwAuth := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "alice" && p == "s3cret" {
				return &sso.AuthResult{UserID: "alice"}, nil
			}
			return nil, errors.New("bad creds")
		}),
	)

	secret := []byte("12345678901234567890") // RFC 4226 §D.1 test vector
	totpAuth := authenticators.NewTOTPAuthenticator(&totpStubStore{secret: secret})
	mfaProvider := authenticators.NewTOTPMFAProvider(totpAuth)

	tstore := tenantmemory.New()
	if err := tstore.PutTenant(context.Background(), residencyTenant(true)); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}

	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithIssuer("mfa-residency-test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRiskScorer(newStubScorer(spi.DecisionRequireMFA)),
		sso.WithMFAProvider(mfaProvider),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 0),
		sso.WithTenantStore(tstore),
		sso.WithRegionMiddleware(region.HeaderResolver{
			Header:  residencyServingHeader,
			Default: "eu-west-1",
		}, region.MiddlewareOptions{}),
		sso.WithTenantResidencyCheck(0),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, secret
}

// completeMFAFromRegion posts the /auth/mfa second leg with the serving-region
// header set (empty servingRegion → no header → home region).
func completeMFAFromRegion(t *testing.T, ts *httptest.Server, challengeID, method, code, servingRegion string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"mfa_challenge_id": challengeID,
		"mfa_method":       method,
		"code":             code,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/auth/mfa", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if servingRegion != "" {
		req.Header.Set(residencyServingHeader, servingRegion)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /auth/mfa: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// TestResidency_MFASecondLeg_DisallowedRegion_Blocked proves the /auth/mfa
// second leg is gated by the LIVE serving region of THAT request: the
// challenge issues from the home region, but completing it from a disallowed
// region is blocked (403 region_not_allowed, iss present) before any token is
// minted.
func TestResidency_MFASecondLeg_DisallowedRegion_Blocked(t *testing.T) {
	ts, secret := buildMFAResidencyHarness(t)

	// First leg from the home region (no header) → mfa_required + challenge.
	status, body := loginMFA(t, ts)
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want 200 (mfa_required) body=%v", status, body)
	}
	if body["error"] != sso.ErrMFARequired {
		t.Fatalf("error = %v, want mfa_required (body=%v)", body["error"], body)
	}
	chal, _ := body["mfa_challenge_id"].(string)
	if chal == "" {
		t.Fatalf("no mfa_challenge_id; body=%v", body)
	}

	// Second leg from a DISALLOWED region — the mint must be blocked.
	code := validTOTPCode(t, secret)
	status, mfaBody := completeMFAFromRegion(t, ts, chal, authenticators.MethodTOTP, code, "us-east-1")
	if status != http.StatusForbidden {
		t.Fatalf("/auth/mfa from disallowed region status = %d, want 403 (bypass!) body=%v", status, mfaBody)
	}
	if got := mfaBody[sso.KeyError]; got != sso.ErrRegionNotAllowed {
		t.Errorf("error = %v, want %q", got, sso.ErrRegionNotAllowed)
	}
	if _, ok := mfaBody[sso.KeyAccessToken]; ok {
		t.Errorf("blocked /auth/mfa second leg still minted an access_token: %v", mfaBody)
	}
	if iss, ok := mfaBody[sso.KeyIss].(string); !ok || iss == "" {
		t.Errorf("iss missing/empty on residency-blocked /auth/mfa body: %v", mfaBody)
	}
}

// TestResidency_MFASecondLeg_HomeRegion_Mints proves the gate doesn't break
// the happy path: completing the challenge from the home region mints tokens.
func TestResidency_MFASecondLeg_HomeRegion_Mints(t *testing.T) {
	ts, secret := buildMFAResidencyHarness(t)

	status, body := loginMFA(t, ts)
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want 200 body=%v", status, body)
	}
	chal, _ := body["mfa_challenge_id"].(string)
	if chal == "" {
		t.Fatalf("no mfa_challenge_id; body=%v", body)
	}

	code := validTOTPCode(t, secret)
	status, mfaBody := completeMFAFromRegion(t, ts, chal, authenticators.MethodTOTP, code, "") // home.
	if status != http.StatusOK {
		t.Fatalf("/auth/mfa from home region status = %d, want 200 body=%v", status, mfaBody)
	}
	if _, ok := mfaBody[sso.KeyAccessToken].(string); !ok {
		t.Errorf("home-region /auth/mfa minted no access_token: %v", mfaBody)
	}
}
