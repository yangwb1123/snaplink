package ssotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// newACRServer wires a direct-login server whose password authenticator
// reports a fixed AchievedACR (pass "" for the no-ACR case).
func newACRServer(t *testing.T, achievedACR string) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "acr-user"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    "acr-client",
		Secret:                "s",
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "alice" && p == "pw" {
				return &sso.AuthResult{UserID: "acr-user", AchievedACR: achievedACR}, nil
			}
			return nil, errors.New("bad")
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func acrLogin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "acr-client",
		"credential": map[string]string{"username": "alice", "password": "pw"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %s", raw)
	}
	return access
}

// jwtACRClaim decodes a compact JWT payload and returns its acr claim and
// whether the claim was present at all.
func jwtACRClaim(t *testing.T, jwt string) (string, bool) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	v, ok := m["acr"]
	if !ok {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

// TestACR_AchievedACRStampedIntoToken: an authenticator that reports an
// AchievedACR surfaces it as the token's acr claim — the seam the
// core/types.go AchievedACR doc promised but never implemented.
func TestACR_AchievedACRStampedIntoToken(t *testing.T) {
	const acr = "urn:mace:incommon:iap:silver"
	access := acrLogin(t, newACRServer(t, acr))
	got, present := jwtACRClaim(t, access)
	if !present || got != acr {
		t.Errorf("acr = %q present=%v, want %q", got, present, acr)
	}
}

// TestACR_OmittedWhenAuthenticatorReportsNone: an empty AchievedACR keeps
// acr off the wire — byte-identical to the pre-AchievedACR default.
func TestACR_OmittedWhenAuthenticatorReportsNone(t *testing.T) {
	access := acrLogin(t, newACRServer(t, ""))
	if got, present := jwtACRClaim(t, access); present {
		t.Errorf("acr should be omitted when AchievedACR is empty, got %q", got)
	}
}
