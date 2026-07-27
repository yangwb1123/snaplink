package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	consentTTLUser     = "consent-ttl-user"
	consentTTLClientID = "consent-ttl-client"
	consentTTLSecret   = "consent-ttl-secret"
	consentTTLPassword = "cpwd"
)

// buildConsentTTLServer drives the REAL wireConsentStore wiring path — the
// same code the binary runs at boot — with the supplied consent config,
// then wraps the resulting options around a minimal password-auth server so
// the consent gate can be exercised over real HTTP. This proves the YAML
// self_service.consent.max_ttl knob actually reaches sso.WithConsentTTL,
// not merely that the config field parses.
func buildConsentTTLServer(t *testing.T, consentCfg config.ConsentConfig) (*httptest.Server, *appBuilder) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: consentTTLUser})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    consentTTLClientID,
		Secret:                consentTTLSecret,
		Active:                true,
		AllowedScopes:         []string{"openid", "profile"},
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != consentTTLPassword {
				return nil, errors.New("bad credentials")
			}
			return &sso.AuthResult{UserID: consentTTLUser, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5 * time.Minute))

	cfg := &config.Config{}
	cfg.SelfService.Consent = consentCfg
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireConsentStore(); err != nil {
		t.Fatalf("wireConsentStore: %v", err)
	}

	opts := append([]sso.Option{
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	}, b.opts...)

	srv := sso.NewServer(opts...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, b
}

// consentTTLLogin posts to /auth/login for the fixed test user/client,
// optionally presenting a previously-issued consent challenge id.
func consentTTLLogin(t *testing.T, srv *httptest.Server, challengeID string) (int, map[string]any) {
	t.Helper()
	req := map[string]any{
		"provider":   authenticators.MethodPassword,
		"client_id":  consentTTLClientID,
		"credential": map[string]string{"username": consentTTLUser, "password": consentTTLPassword},
		"scope":      []string{"openid"},
	}
	if challengeID != "" {
		req[sso.KeyConsentChallengeID] = challengeID
	}
	raw, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// approveConsentTTL drives the two-step consent handshake (consent_required
// -> approve with the issued challenge id) and returns the final response.
func approveConsentTTL(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	_, body := consentTTLLogin(t, srv, "")
	if body["error"] != sso.ErrConsentRequired {
		t.Fatalf("expected consent_required on first login, got %v", body)
	}
	challengeID, _ := body[sso.KeyConsentChallengeID].(string)
	if challengeID == "" {
		t.Fatalf("missing %q in consent_required response %v", sso.KeyConsentChallengeID, body)
	}
	status, body2 := consentTTLLogin(t, srv, challengeID)
	if status != http.StatusOK {
		t.Fatalf("approve step: status=%d body=%v", status, body2)
	}
	if _, ok := body2["access_token"].(string); !ok {
		t.Fatalf("approve step: expected access_token, got %v", body2)
	}
	return body2
}

// TestWireConsentStore_MaxTTLStampsGrantExpiry is the gap-closing test: an
// operator setting self_service.consent.max_ttl in YAML must see every
// recorded consent grant stamped with a matching ExpiresAt. Before this
// fix, wireConsentStore had no TTL field to read and never called
// sso.WithConsentTTL, so the SDK-level ceiling was permanently unreachable
// from the stock binary — grants lived forever no matter what an operator
// configured.
func TestWireConsentStore_MaxTTLStampsGrantExpiry(t *testing.T) {
	t.Parallel()
	const maxTTL = time.Hour
	srv, b := buildConsentTTLServer(t, config.ConsentConfig{
		SelfServiceStoreConfig: config.SelfServiceStoreConfig{Backend: "memory"},
		MaxTTL:                 maxTTL,
	})

	before := time.Now()
	approveConsentTTL(t, srv)

	grant, err := b.consentStore.GetConsent(context.Background(), consentTTLUser, consentTTLClientID)
	if err != nil {
		t.Fatalf("GetConsent: %v", err)
	}
	if grant.ExpiresAt.IsZero() {
		t.Fatal("grant.ExpiresAt is zero — self_service.consent.max_ttl did not reach WithConsentTTL")
	}
	wantExpiry := before.Add(maxTTL)
	if grant.ExpiresAt.Before(wantExpiry.Add(-time.Minute)) || grant.ExpiresAt.After(wantExpiry.Add(time.Minute)) {
		t.Errorf("grant.ExpiresAt=%v, want ~%v (GrantedAt+max_ttl)", grant.ExpiresAt, wantExpiry)
	}
}

// TestWireConsentStore_NoMaxTTLLeavesGrantsPermanent proves the default
// (max_ttl unset, the zero value) stays byte-identical to prior behavior:
// no ExpiresAt is stamped and the grant never server-side-expires.
func TestWireConsentStore_NoMaxTTLLeavesGrantsPermanent(t *testing.T) {
	t.Parallel()
	srv, b := buildConsentTTLServer(t, config.ConsentConfig{
		SelfServiceStoreConfig: config.SelfServiceStoreConfig{Backend: "memory"},
	})

	approveConsentTTL(t, srv)

	grant, err := b.consentStore.GetConsent(context.Background(), consentTTLUser, consentTTLClientID)
	if err != nil {
		t.Fatalf("GetConsent: %v", err)
	}
	if !grant.ExpiresAt.IsZero() {
		t.Errorf("grant.ExpiresAt=%v, want zero (no max_ttl configured)", grant.ExpiresAt)
	}
}
