package sso_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const federatedRoundTripProvider = "federated-round-trip"

type federatedRoundTripAuth struct {
	mu            sync.Mutex
	callbackCalls int
}

func (*federatedRoundTripAuth) Name() string { return federatedRoundTripProvider }

func (*federatedRoundTripAuth) LoginURL(state string) string {
	return "https://upstream.example/authorize?" + url.Values{"state": {state}}.Encode()
}

func (*federatedRoundTripAuth) Authenticate(context.Context, *sso.AuthRequest) (*sso.AuthResult, error) {
	return nil, errors.New("direct authentication is not supported")
}

func (a *federatedRoundTripAuth) Callback(_ context.Context, state *sso.CallbackState) (*sso.AuthResult, error) {
	a.mu.Lock()
	a.callbackCalls++
	a.mu.Unlock()
	if state == nil || state.Code != "upstream-code" {
		return nil, errors.New("bad upstream callback")
	}
	return &sso.AuthResult{
		UserID: rcovUser, Provider: federatedRoundTripProvider,
		AuthMethods: []string{"fed"}, Attributes: map[string]string{"email_verified": "true"},
	}, nil
}

func (a *federatedRoundTripAuth) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.callbackCalls
}

func configureFederatedClient(t *testing.T, server *rcovServer, skipConsent bool) {
	t.Helper()
	client, err := server.clients.Get(context.Background(), rcovClient)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	client.AllowedAuthenticators = []string{"password", federatedRoundTripProvider}
	client.LoginPageURI = "https://login.example.test/authorize?theme=dark"
	client.SkipConsent = skipConsent
	server.clients.AddSeed(client)
}

func startFederatedAuthorization(t *testing.T, server *rcovServer, state string) string {
	t.Helper()
	q := url.Values{
		"provider":              {federatedRoundTripProvider},
		"client_id":             {rcovClient},
		"response_type":         {"code"},
		"redirect_uri":          {rcovRedirect},
		"state":                 {state},
		"scope":                 {"openid profile"},
		"code_challenge":        {strings.Repeat("A", 43)},
		"code_challenge_method": {"S256"},
	}
	resp := federatedGetNoFollow(t, server.http.URL+"/auth/login?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("federated start = %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	_ = resp.Body.Close()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse upstream location: %v", err)
	}
	upstreamState := u.Query().Get("state")
	if !strings.HasPrefix(upstreamState, federatedRoundTripProvider+":slf.") || upstreamState == state {
		t.Fatalf("upstream state = %q, want opaque server correlation", upstreamState)
	}
	return upstreamState
}

func federatedGetNoFollow(t *testing.T, target string) *http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return resp
}

func finishUpstreamCallback(
	t *testing.T, server *rcovServer, upstreamState string, extra url.Values,
) string {
	t.Helper()
	q := url.Values{"state": {upstreamState}}
	for key, values := range extra {
		q[key] = values
	}
	resp := federatedGetNoFollow(t, server.http.URL+"/auth/callback?"+q.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("upstream callback = %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	_ = resp.Body.Close()
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "https" || u.Host != "login.example.test" {
		t.Fatalf("hosted-login continuation = %q err=%v", location, err)
	}
	if u.Query().Get("state") != "" || u.Query().Get("client_id") != rcovClient ||
		u.Query().Get("redirect_uri") != rcovRedirect || u.Query().Get("theme") != "dark" {
		t.Fatalf("unsafe/incomplete hosted-login continuation: %s", location)
	}
	fragment, err := url.ParseQuery(u.Fragment)
	if err != nil || fragment.Get("login_transaction_id") == "" {
		t.Fatalf("continuation fragment = %q err=%v", u.Fragment, err)
	}
	return fragment.Get("login_transaction_id")
}

func resumeFederatedAuthorization(
	t *testing.T, server *rcovServer, transactionID string,
) (int, map[string]any) {
	t.Helper()
	return rcovPostJSON(t, server.http.URL+"/auth/login", "", map[string]any{
		"client_id": rcovClient, "login_transaction_id": transactionID,
	})
}

func TestFederatedAuthorization_CodeRoundTripAndReplayDefense(t *testing.T) {
	t.Parallel()
	auth := &federatedRoundTripAuth{}
	server := rcovNewServer(t, sso.WithAuthenticator(auth))
	configureFederatedClient(t, server, true)

	upstreamState := startFederatedAuthorization(t, server, "rp-state")
	transaction := finishUpstreamCallback(t, server, upstreamState, url.Values{
		"provider": {federatedRoundTripProvider}, "code": {"upstream-code"},
	})
	status, body := resumeFederatedAuthorization(t, server, transaction)
	if status != http.StatusOK || body["code"] == nil || body["state"] != "rp-state" ||
		body["redirect_uri_validated"] != true || body["redirect_uri"] != rcovRedirect {
		t.Fatalf("federated authorization = %d %v", status, body)
	}

	resp := federatedGetNoFollow(t, server.http.URL+"/auth/callback?"+url.Values{
		"state": {upstreamState}, "code": {"upstream-code"},
	}.Encode())
	if resp.StatusCode != http.StatusBadRequest || auth.calls() != 1 {
		t.Fatalf("callback replay status=%d calls=%d", resp.StatusCode, auth.calls())
	}
	_ = resp.Body.Close()
	status, body = resumeFederatedAuthorization(t, server, transaction)
	if status != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("continuation replay = %d %v", status, body)
	}
}

func TestFederatedAuthorization_UpstreamErrorAndProviderTamper(t *testing.T) {
	t.Parallel()
	auth := &federatedRoundTripAuth{}
	server := rcovNewServer(t, sso.WithAuthenticator(auth))
	configureFederatedClient(t, server, true)

	deniedState := startFederatedAuthorization(t, server, "denied-state")
	transaction := finishUpstreamCallback(t, server, deniedState, url.Values{
		"error": {"access_denied"},
	})
	status, body := resumeFederatedAuthorization(t, server, transaction)
	if status != http.StatusForbidden || body["error"] != "access_denied" ||
		body["state"] != "denied-state" || auth.calls() != 0 {
		t.Fatalf("upstream denial = %d %v calls=%d", status, body, auth.calls())
	}

	tamperedState := startFederatedAuthorization(t, server, "tampered-state")
	transaction = finishUpstreamCallback(t, server, tamperedState, url.Values{
		"provider": {"attacker-provider"}, "code": {"upstream-code"},
	})
	status, body = resumeFederatedAuthorization(t, server, transaction)
	if status != http.StatusUnauthorized || body["error"] != "callback_failed" ||
		body["state"] != "tampered-state" || auth.calls() != 0 {
		t.Fatalf("provider tamper = %d %v calls=%d", status, body, auth.calls())
	}
}

func TestFederatedAuthorization_ResumesMFAAndConsentGates(t *testing.T) {
	t.Parallel()
	auth := &federatedRoundTripAuth{}
	server := rcovNewServer(t,
		sso.WithAuthenticator(auth),
		sso.WithRiskScorer(rcovRequireMFAScorer{}),
		sso.WithMFAProvider(rcovTOTPProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 5*time.Minute),
	)
	configureFederatedClient(t, server, false)

	upstreamState := startFederatedAuthorization(t, server, "gated-state")
	transaction := finishUpstreamCallback(t, server, upstreamState, url.Values{
		"code": {"upstream-code"},
	})
	status, body := resumeFederatedAuthorization(t, server, transaction)
	if status != http.StatusOK || body["error"] != "mfa_required" {
		t.Fatalf("federated resume = %d %v, want MFA", status, body)
	}
	status, body = rcovPostJSON(t, server.http.URL+"/auth/mfa", "", map[string]any{
		"mfa_challenge_id": body["mfa_challenge_id"],
		"mfa_method":       "totp", "code": "123456",
	})
	if status != http.StatusOK || body["error"] != "consent_required" ||
		body["login_transaction_id"] == nil {
		t.Fatalf("federated MFA = %d %v, want consent", status, body)
	}
	status, body = rcovPostJSON(t, server.http.URL+"/auth/login", "", map[string]any{
		"client_id":            rcovClient,
		"login_transaction_id": body["login_transaction_id"],
		"consent_challenge_id": body["consent_challenge_id"],
		"consent_decision":     "allow",
	})
	if status != http.StatusOK || body["code"] == nil || body["state"] != "gated-state" {
		t.Fatalf("federated consent = %d %v, want authorization code", status, body)
	}
}
