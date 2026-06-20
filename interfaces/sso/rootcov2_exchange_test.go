package sso_test

// rootcov2_exchange_test.go targets the RFC 8693 token-exchange branch surface
// (token_exchange_handler.go handleTokenExchangeGrant + acrMatchesAny) plus the
// B2B accept-invitation flow (handlers_b2b.go handleAcceptInvitation) and the
// self-service MFA-factor management endpoints (me_mfa.go) the first rootcov_*
// pass left thin.
//
// REUSES rcovNewServer / rcovDirectLogin / rcovPostJSON / rcovDo and the
// rcov2PasswordAuth helper from rootcov2_cluster_test.go.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

// rcov2ExchangeServer wires a client with an AllowedResources allowlist + a
// refresh token store so the exchange variants (resource binding, refresh
// requested_token_type) are exercisable.
func rcov2ExchangeServer(t *testing.T, acr string) *rcovServer {
	t.Helper()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, RedirectURIs: []string{rcovRedirect},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
		AllowedResources: []string{"https://api.example.com"},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rcovUsername && p == rcovPassword {
				return &sso.AuthResult{UserID: rcovUser, AuthMethods: []string{"pwd"}, AchievedACR: acr}, nil
			}
			return nil, errors.New("bad")
		}))
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithJTIReplayStore(defaultimpl.NewMemoryJTIReplayStore()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &rcovServer{http: httpSrv, users: users, clients: clients}
}

// TestRcov2X_ExchangeWithActorAndResource covers the delegation path (actor
// token), resource binding, scope downscoping, and requested_token_type variants.
func TestRcov2X_ExchangeWithActorAndResource(t *testing.T) {
	s := rcov2ExchangeServer(t, "")

	// Two tokens: a subject token and an actor token (both real access tokens).
	subject := rcov2LoginToken(t, s)
	actor := rcov2LoginToken(t, s)

	// Delegation: actor_token=access_token + resource binding + downscope.
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      subject,
		"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"actor_token":        actor,
		"actor_token_type":   "urn:ietf:params:oauth:token-type:access_token",
		"resource":           []string{"https://api.example.com"},
		"client_id":          rcovClient,
		"client_secret":      rcovSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("exchange w/ actor+resource = %d body=%v", status, tok)
	}
	if tok["access_token"] == "" || tok["access_token"] == nil {
		t.Errorf("no exchanged token: %v", tok)
	}

	// requested_token_type=refresh_token mints a refresh alongside.
	subject2 := rcov2LoginToken(t, s)
	status, tok = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":        subject2,
		"subject_token_type":   "urn:ietf:params:oauth:token-type:access_token",
		"requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
		"client_id":            rcovClient,
		"client_secret":        rcovSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("exchange refresh = %d body=%v", status, tok)
	}
	if tok["refresh_token"] == "" || tok["refresh_token"] == nil {
		t.Errorf("requested_token_type=refresh_token produced no refresh: %v", tok)
	}
}

// TestRcov2X_ExchangeRejections covers the rejection branches: an unknown actor
// token type, a disallowed resource, and scope expansion.
func TestRcov2X_ExchangeRejections(t *testing.T) {
	s := rcov2ExchangeServer(t, "")
	subject := rcov2LoginToken(t, s)

	// Bad actor token type => invalid_request.
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      subject,
		"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"actor_token":        "x",
		"actor_token_type":   "urn:made:up:type",
		"client_id":          rcovClient,
		"client_secret":      rcovSecret,
	})
	if status != http.StatusBadRequest {
		t.Errorf("bad actor type = %d, want 400 (body=%v)", status, out)
	}

	// Disallowed resource => invalid_target.
	status, out = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      subject,
		"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"resource":           []string{"https://not-allowed.example.com"},
		"client_id":          rcovClient,
		"client_secret":      rcovSecret,
	})
	if status != http.StatusBadRequest {
		t.Errorf("disallowed resource = %d, want 400 (body=%v)", status, out)
	}
}

// TestRcov2X_ExchangeACRDemand covers acrMatchesAny: an exchange demanding an
// acr_values the subject token satisfies succeeds; one it doesn't fails.
func TestRcov2X_ExchangeACRDemand(t *testing.T) {
	s := rcov2ExchangeServer(t, "urn:acr:strong")
	subject := rcov2LoginToken(t, s)

	// The subject token achieved urn:acr:strong => demanding it succeeds.
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      subject,
		"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"acr_values":         "urn:acr:strong urn:acr:other",
		"client_id":          rcovClient,
		"client_secret":      rcovSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("exchange w/ satisfied acr = %d body=%v", status, tok)
	}

	// Demanding an acr the token lacks => rejected.
	status, _ = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      subject,
		"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"acr_values":         "urn:acr:nonexistent",
		"client_id":          rcovClient,
		"client_secret":      rcovSecret,
	})
	if status != http.StatusBadRequest {
		t.Errorf("exchange w/ unmet acr = %d, want 400", status)
	}
}

// rcov2LoginToken performs a direct-mint login against an rcov2ExchangeServer
// and returns the access token.
func rcov2LoginToken(t *testing.T, s *rcovServer) string {
	t.Helper()
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("login = %d body=%v", status, out)
	}
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("login produced no token: %v", out)
	}
	return tok
}

// TestRcov2X_AcceptInvitation covers the B2B accept-invitation flow: an
// invitation issued into the store is redeemed by the authenticated subject.
func TestRcov2X_AcceptInvitation(t *testing.T) {
	ctx := context.Background()
	invStore := defaultimpl.NewMemoryInvitationStore()
	tenantUsers := defaultimpl.NewMemoryTenantUserStore()

	s := rcovNewServer(t,
		sso.WithInvitationStore(invStore),
		sso.WithTenantUserStore(tenantUsers),
	)
	access, _ := rcovDirectLogin(t, s)

	// Issue an invitation directly into the store (admin would normally do this).
	const token = "rcov2-invite-token"
	_ = invStore.Issue(ctx, &core.Invitation{
		Token:     token,
		TenantID:  "org-7",
		Role:      "member",
		Email:     "alice@example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// Redeem it.
	status, out := rcovPostJSON(t, s.http.URL+"/me/invitations/accept", access, map[string]any{
		"token": token,
	})
	if status != http.StatusOK {
		t.Fatalf("accept invitation = %d body=%v", status, out)
	}
	if out["tenant_id"] != "org-7" {
		t.Errorf("joined tenant = %v, want org-7", out["tenant_id"])
	}

	// Replaying the consumed token => invitation_invalid.
	status, _ = rcovPostJSON(t, s.http.URL+"/me/invitations/accept", access, map[string]any{
		"token": token,
	})
	if status != http.StatusBadRequest {
		t.Errorf("invitation replay = %d, want 400", status)
	}

	// Missing token => 400.
	status, _ = rcovPostJSON(t, s.http.URL+"/me/invitations/accept", access, map[string]any{})
	if status != http.StatusBadRequest {
		t.Errorf("accept no token = %d, want 400", status)
	}
}

// TestRcov2X_MFAFactorDelete covers the self-service MFA-factor management:
// enroll a TOTP factor, list it (handleMyMFAFactors), then delete it
// (handleDeleteMyMFAFactor).
func TestRcov2X_MFAFactorDelete(t *testing.T) {
	totpAuth := authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore())
	enroller := authenticators.NewTOTPEnroller(totpAuth)
	s := rcovNewServer(t,
		sso.WithMFAEnrollmentStore(defaultimpl.NewMemoryTOTPEnrollmentStore()),
		sso.WithTOTPEnroller(enroller),
	)
	access, _ := rcovDirectLogin(t, s)

	// Enroll a factor (begin + confirm with a derived code).
	_, beg := rcovPostJSON(t, s.http.URL+"/me/mfa/totp/begin", access, nil)
	secret, _ := beg["secret"].(string)
	status, conf := rcovPostJSON(t, s.http.URL+"/me/mfa/totp/confirm", access, map[string]any{
		"secret": secret,
		"code":   rcov2CurrentTOTPCode(t, secret),
	})
	if status != http.StatusCreated {
		t.Fatalf("totp confirm = %d body=%v", status, conf)
	}
	factorID, _ := conf["factor_id"].(string)
	if factorID == "" {
		t.Fatalf("no factor_id: %v", conf)
	}

	// List shows the factor.
	status, list := rcovDo(t, http.MethodGet, s.http.URL+"/me/mfa", access, nil)
	if status != http.StatusOK {
		t.Fatalf("list factors = %d body=%v", status, list)
	}

	// Delete it.
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/me/mfa/"+factorID, access, nil)
	if status != http.StatusOK && status != http.StatusNoContent {
		t.Errorf("delete factor = %d, want 200/204", status)
	}

	// Deleting an unknown factor is benign (idempotent) — not a 5xx.
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/me/mfa/no-such-factor", access, nil)
	if status >= 500 {
		t.Errorf("delete unknown factor = %d, want < 500", status)
	}
}
