package sso_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const loginTransactionClient = "login-transaction-client"

func newLoginTransactionServer(
	t *testing.T,
) (*rcovServer, *defaultimpl.MemoryTrustedDeviceStore) {
	t.Helper()
	trusted := defaultimpl.NewMemoryTrustedDeviceStore()
	server := rcovNewServer(t,
		sso.WithRiskScorer(rcovRequireMFAScorer{}),
		sso.WithMFAProvider(rcovTOTPProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 5*time.Minute),
		sso.WithTrustedDeviceStore(trusted, 24*time.Hour),
	)
	server.clients.AddSeed(&sso.Client{
		ID: loginTransactionClient, Name: "Transaction Client",
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt", Active: true, SkipConsent: false,
	})
	return server, trusted
}

func startMFAConsentTransaction(
	t *testing.T, server *rcovServer, trustDevice bool,
) (string, string, map[string]any) {
	t.Helper()
	status, body := rcovPostJSON(t, server.http.URL+"/auth/login", "", map[string]any{
		"provider": "password", "client_id": loginTransactionClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "profile"},
	})
	if status != http.StatusOK || body["error"] != "mfa_required" {
		t.Fatalf("primary login = %d %v, want mfa_required", status, body)
	}
	status, body = rcovPostJSON(t, server.http.URL+"/auth/mfa", "", map[string]any{
		"mfa_challenge_id": body["mfa_challenge_id"],
		"mfa_method":       "totp",
		"code":             "123456",
		"trust_device":     trustDevice,
	})
	if status != http.StatusOK || body["error"] != "consent_required" {
		t.Fatalf("MFA completion = %d %v, want consent_required", status, body)
	}
	transaction, _ := body["login_transaction_id"].(string)
	consent, _ := body["consent_challenge_id"].(string)
	if transaction == "" || consent == "" {
		t.Fatalf("continuation identifiers missing: %v", body)
	}
	return transaction, consent, body
}

func TestLoginTransaction_MFAConsentAllowAndReplay(t *testing.T) {
	t.Parallel()
	server, _ := newLoginTransactionServer(t)
	transaction, consent, pending := startMFAConsentTransaction(t, server, true)
	if pending["device_token"] != nil {
		t.Fatalf("trusted-device grant minted before consent: %v", pending)
	}
	payload := map[string]any{
		"client_id": loginTransactionClient, "login_transaction_id": transaction,
		"consent_challenge_id": consent, "consent_decision": "allow",
	}
	status, body := rcovPostJSON(t, server.http.URL+"/auth/login", "", payload)
	if status != http.StatusOK || body["access_token"] == nil || body["device_token"] == nil {
		t.Fatalf("consent allow = %d %v, want tokens", status, body)
	}
	status, body = rcovPostJSON(t, server.http.URL+"/auth/login", "", payload)
	if status != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("transaction replay = %d %v, want invalid_request", status, body)
	}
}

func TestLoginTransaction_PrimaryConsentDoesNotReplayCredentials(t *testing.T) {
	t.Parallel()
	server := rcov2ConsentServer(t)
	status, body := rcovPostJSON(t, server.http.URL+"/auth/login", "", map[string]any{
		"provider": "password", "client_id": rcov2ConsentClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid"},
	})
	transaction, _ := body["login_transaction_id"].(string)
	consent, _ := body["consent_challenge_id"].(string)
	if status != http.StatusOK || transaction == "" || consent == "" {
		t.Fatalf("primary consent continuation = %d %v", status, body)
	}
	status, body = rcovPostJSON(t, server.http.URL+"/auth/login", "", map[string]any{
		"client_id": rcov2ConsentClient, "login_transaction_id": transaction,
		"consent_challenge_id": consent, "consent_decision": "allow",
	})
	if status != http.StatusOK || body["access_token"] == nil {
		t.Fatalf("credential-free consent continuation = %d %v", status, body)
	}
}

func TestLoginTransaction_ConsentDenyDoesNotTrustDevice(t *testing.T) {
	t.Parallel()
	server, trusted := newLoginTransactionServer(t)
	transaction, consent, _ := startMFAConsentTransaction(t, server, true)
	status, body := rcovPostJSON(t, server.http.URL+"/auth/login", "", map[string]any{
		"client_id": loginTransactionClient, "login_transaction_id": transaction,
		"consent_challenge_id": consent, "consent_decision": "deny",
	})
	if status != http.StatusForbidden || body["error"] != "access_denied" {
		t.Fatalf("consent deny = %d %v, want access_denied", status, body)
	}
	devices, err := trusted.ListByUser(context.Background(), rcovUser)
	if err != nil || len(devices) != 0 {
		t.Fatalf("denied request created trusted device: devices=%v err=%v", devices, err)
	}
}

func TestAuthorizationError_JARMPostReturnsSignedEnvelope(t *testing.T) {
	t.Parallel()
	server := rcovNewServer(t, sso.WithJARM(defaultimpl.NewEd25519JWTIssuer()))
	status, body := rcovPostJSON(t, server.http.URL+"/auth/login", "", map[string]any{
		"provider":      "password",
		"client_id":     rcovClient,
		"credential":    map[string]string{"username": rcovUsername, "password": "wrong"},
		"response_type": "code",
		"response_mode": "query.jwt",
		"redirect_uri":  rcovRedirect,
		"state":         "signed-error-state",
	})
	response, _ := body["response"].(string)
	if status != http.StatusOK || len(strings.Split(response, ".")) != 3 {
		t.Fatalf("JARM error envelope = %d %v", status, body)
	}
	if body["error"] != nil || body["redirect_uri_validated"] != nil {
		t.Fatalf("unsigned authorization fields escaped JARM: %v", body)
	}
}

func TestAuthorizationError_RedirectAttestationRequiresRegisteredURI(t *testing.T) {
	t.Parallel()
	server := rcovNewServer(t)
	login := map[string]any{
		"provider": "password", "client_id": rcovClient,
		"credential":    map[string]string{"username": rcovUsername, "password": "wrong"},
		"response_type": "code", "redirect_uri": rcovRedirect,
		"state": "error-state",
	}
	_, body := rcovPostJSON(t, server.http.URL+"/auth/login", "", login)
	if body["redirect_uri_validated"] != true || body["error"] == nil {
		t.Fatalf("registered redirect was not attested: %v", body)
	}
	login["redirect_uri"] = "https://attacker.example/callback"
	_, body = rcovPostJSON(t, server.http.URL+"/auth/login", "", login)
	if body["redirect_uri_validated"] != nil {
		t.Fatalf("unregistered redirect was attested: %v", body)
	}
}
