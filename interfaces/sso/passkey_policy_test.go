package sso_test

// passkey_policy_test.go covers the require-passkey enrollment-nudge policy
// (WithPasskeyPolicy, domains/authenticators/passkeypolicy): the login
// response's advisory passkey_enrollment_recommended / passkey_recovery_allowed
// fields must be absent when the feature is unwired (byte-identical default),
// present exactly when the policy is on AND the user has no enrolled
// passkey, and the risk-based "periodic" frequency must degrade to "once"
// behavior when no trust.TrustScorer is wired.
//
// REUSES rcovNewServer / rcovPostJSON from rootcov_flow_test.go.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/authenticators/passkeypolicy"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/trust"
)

// ppLoginBody is the standard rcov direct-mint login request body — pulled
// out here (rather than reusing rcovDirectLogin, which only returns the
// token strings) because these tests need the full response map to inspect
// the nudge fields.
func ppLoginBody() map[string]any {
	return map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid"},
	}
}

// TestPasskeyPolicy_OffByDefault proves a build without WithPasskeyPolicy
// carries neither nudge field — byte-identical to a build without the
// feature, matching the historical login response shape exactly.
func TestPasskeyPolicy_OffByDefault(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t) // no WithPasskeyPolicy
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", ppLoginBody())
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if _, ok := out["passkey_enrollment_recommended"]; ok {
		t.Errorf("passkey_enrollment_recommended present with no WithPasskeyPolicy wired: %v", out)
	}
	if _, ok := out["passkey_recovery_allowed"]; ok {
		t.Errorf("passkey_recovery_allowed present with no WithPasskeyPolicy wired: %v", out)
	}
}

// TestPasskeyPolicy_NudgesWhenMissingPasskey proves the default frequency
// (PromptOnce, the empty PromptFrequency) nudges every login for a user
// with no registered WebAuthn factor, and never blocks or degrades the
// login itself (tokens are still minted).
func TestPasskeyPolicy_NudgesWhenMissingPasskey(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithPasskeyPolicy(passkeypolicy.Policy{RequirePasskey: true}))
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", ppLoginBody())
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if out["access_token"] == "" || out["access_token"] == nil {
		t.Errorf("passkey policy must never block login: no access_token in %v", out)
	}
	if recommended, _ := out["passkey_enrollment_recommended"].(bool); !recommended {
		t.Errorf("passkey_enrollment_recommended = %v, want true (user has no passkey)", out["passkey_enrollment_recommended"])
	}
	if _, ok := out["passkey_recovery_allowed"]; ok {
		t.Errorf("passkey_recovery_allowed present when RecoveryAllowed=false: %v", out)
	}
}

// TestPasskeyPolicy_NoNudgeWhenPasskeyEnrolled proves a user who already has
// a registered WebAuthn factor is never nudged.
func TestPasskeyPolicy_NoNudgeWhenPasskeyEnrolled(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithPasskeyPolicy(passkeypolicy.Policy{RequirePasskey: true}))
	s.mfaEnr.AddFactor(rcovUser, core.MFAEnrolledFactor{ID: "cred-1", Method: "webauthn"})

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", ppLoginBody())
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if _, ok := out["passkey_enrollment_recommended"]; ok {
		t.Errorf("passkey_enrollment_recommended present for a user who already has a passkey: %v", out)
	}
}

// TestPasskeyPolicy_PromptNeverSuppressesNudge proves "never" stages the
// policy without ever surfacing the UX prompt, even for a user with no
// passkey.
func TestPasskeyPolicy_PromptNeverSuppressesNudge(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithPasskeyPolicy(passkeypolicy.Policy{
		RequirePasskey:  true,
		PromptFrequency: passkeypolicy.PromptNever,
	}))
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", ppLoginBody())
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if _, ok := out["passkey_enrollment_recommended"]; ok {
		t.Errorf("passkey_enrollment_recommended present under PromptNever: %v", out)
	}
}

// TestPasskeyPolicy_RecoveryAllowedEchoed proves RecoveryAllowed rides
// alongside the nudge only when both the nudge fires AND the policy opts in.
func TestPasskeyPolicy_RecoveryAllowedEchoed(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithPasskeyPolicy(passkeypolicy.Policy{
		RequirePasskey:  true,
		RecoveryAllowed: true,
	}))
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", ppLoginBody())
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if recommended, _ := out["passkey_enrollment_recommended"].(bool); !recommended {
		t.Errorf("expected the nudge to fire: %v", out)
	}
	if allowed, _ := out["passkey_recovery_allowed"].(bool); !allowed {
		t.Errorf("passkey_recovery_allowed = %v, want true", out["passkey_recovery_allowed"])
	}
}

// TestPasskeyPolicy_PeriodicWithoutScorerDegradesToOnce proves that
// PromptPeriodic with NO trust.TrustScorer wired still nudges — fail-open
// toward MORE nudging (never toward suppressing the feature the operator
// turned on, and never toward blocking the login).
func TestPasskeyPolicy_PeriodicWithoutScorerDegradesToOnce(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithPasskeyPolicy(passkeypolicy.Policy{
		RequirePasskey:  true,
		PromptFrequency: passkeypolicy.PromptPeriodic,
	})) // no WithTrustScorer
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", ppLoginBody())
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if recommended, _ := out["passkey_enrollment_recommended"].(bool); !recommended {
		t.Errorf("periodic with no scorer wired must degrade to once (always nudge): %v", out)
	}
}

// fixedScorer is a trust.TrustScorer stub returning a constant Value —
// exercises the risk-based periodic cadence without wiring the full
// geo/IP-reputation/behavior composite.
type fixedScorer struct{ value float64 }

func (f fixedScorer) Score(context.Context, trust.TrustSignals) (trust.TrustScore, error) {
	return trust.TrustScore{Value: f.value}, nil
}
func (f fixedScorer) Name() string { return "fixed" }

// TestPasskeyPolicy_PeriodicHighRiskNudges proves a HIGH-risk login (low
// trust value) nudges even under "periodic".
func TestPasskeyPolicy_PeriodicHighRiskNudges(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t,
		sso.WithPasskeyPolicy(passkeypolicy.Policy{RequirePasskey: true, PromptFrequency: passkeypolicy.PromptPeriodic}),
		sso.WithTrustScorer(fixedScorer{value: 0.1}), // trust=0.1 -> risk=0.9, >= HighRiskThreshold
	)
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", ppLoginBody())
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if recommended, _ := out["passkey_enrollment_recommended"].(bool); !recommended {
		t.Errorf("high-risk periodic login must nudge: %v", out)
	}
}

// TestPasskeyPolicy_PeriodicLowRiskThrottles proves a LOW-risk login (high
// trust value) is throttled — no nudge — under "periodic".
func TestPasskeyPolicy_PeriodicLowRiskThrottles(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t,
		sso.WithPasskeyPolicy(passkeypolicy.Policy{RequirePasskey: true, PromptFrequency: passkeypolicy.PromptPeriodic}),
		sso.WithTrustScorer(fixedScorer{value: 0.95}), // trust=0.95 -> risk=0.05, < HighRiskThreshold
	)
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", ppLoginBody())
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if _, ok := out["passkey_enrollment_recommended"]; ok {
		t.Errorf("low-risk periodic login must be throttled (no nudge): %v", out)
	}
}

// TestPasskeyPolicy_NoMFAEnrollmentStoreNeverNudges proves the nudge is
// inert without an MFAEnrollmentStore wired — there is no factor data to
// check, so applyPasskeyPolicySignal must not guess. Built directly (not via
// rcovNewServer, which always wires an MFAEnrollmentStore) with the minimal
// option set a direct-mint login needs, mirroring
// TestRcov2L_DiscoveryCacheInvalidate's bare-server style.
func TestPasskeyPolicy_NoMFAEnrollmentStoreNeverNudges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, RedirectURIs: []string{rcovRedirect},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rcovUsername && p == rcovPassword {
				return &sso.AuthResult{UserID: rcovUser}, nil
			}
			return nil, errors.New("bad credentials")
		}))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPasskeyPolicy(passkeypolicy.Policy{RequirePasskey: true}),
		// deliberately no WithMFAEnrollmentStore
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", ppLoginBody())
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if _, ok := out["passkey_enrollment_recommended"]; ok {
		t.Errorf("passkey_enrollment_recommended present without an MFAEnrollmentStore: %v", out)
	}
}
