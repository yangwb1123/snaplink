package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	uiUser   = "u-userinfo"
	uiClient = "ui-client"
	uiSecret = "ui-secret"
)

func newUserInfoServer(t *testing.T) (*httptest.Server, func(scopes []string) string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{
		ID:    uiUser,
		Email: "alice@example.com",
		Name:  "Alice Liddell",
		Attributes: map[string]string{
			"email_verified":        "true",
			"given_name":            "Alice",
			"family_name":           "Liddell",
			"picture":               "https://cdn/alice.jpg",
			"preferred_username":    "alice",
			"phone_number":          "+15551234567",
			"phone_number_verified": "true",
			"address":               "Wonderland",
			"custom_attr":           "not-in-oidc",
		},
	})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: uiClient, Secret: uiSecret,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt", Active: true,
	})
	// AuthResult.Attributes is the authoritative source projected into
	// the User on upsert — populate the full OIDC claim set here so the
	// post-login User has everything we want to test.
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{
				UserID:   uiUser,
				Provider: "password",
				Attributes: map[string]string{
					"email":                 "alice@example.com",
					"name":                  "Alice Liddell",
					"email_verified":        "true",
					"given_name":            "Alice",
					"family_name":           "Liddell",
					"picture":               "https://cdn/alice.jpg",
					"preferred_username":    "alice",
					"phone_number":          "+15551234567",
					"phone_number_verified": "true",
					"address":               "Wonderland",
					"custom_attr":           "not-in-oidc",
				},
			}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	loginWithScopes := func(scopes []string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  uiClient,
			"credential": map[string]string{"username": "x", "password": "y"},
			"scope":      scopes,
		})
		resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", io.NopCloser(byteReader(body)))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		tok, _ := out["access_token"].(string)
		return tok
	}
	return httpSrv, loginWithScopes
}

func byteReader(b []byte) *byteSliceReader { return &byteSliceReader{b: b} }

type byteSliceReader struct {
	b []byte
	i int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func fetchUserInfo(t *testing.T, srv *httptest.Server, bearer string) map[string]any {
	t.Helper()
	r, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status = %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// ---------- OIDC path (openid scope present) ----------

func TestUserInfo_OIDC_OpenIDOnlyReturnsSubOnly(t *testing.T) {
	srv, login := newUserInfoServer(t)
	bearer := login([]string{"openid"})
	out := fetchUserInfo(t, srv, bearer)
	if out["sub"] != uiUser {
		t.Errorf("sub = %v want %q", out["sub"], uiUser)
	}
	// No email/profile scope → those claims MUST NOT be returned.
	for _, k := range []string{"email", "name", "given_name", "phone_number"} {
		if out[k] != nil {
			t.Errorf("claim %q leaked without scope: %v", k, out[k])
		}
	}
}

func TestUserInfo_OIDC_EmailScopeReturnsEmailAndVerified(t *testing.T) {
	srv, login := newUserInfoServer(t)
	bearer := login([]string{"openid", "email"})
	out := fetchUserInfo(t, srv, bearer)
	if out["email"] != "alice@example.com" {
		t.Errorf("email = %v", out["email"])
	}
	if v, ok := out["email_verified"].(bool); !ok || !v {
		t.Errorf("email_verified = %v want true", out["email_verified"])
	}
	// Profile claims absent without profile scope.
	if out["name"] != nil {
		t.Errorf("name leaked: %v", out["name"])
	}
}

func TestUserInfo_OIDC_ProfileScopeReturnsProfileClaims(t *testing.T) {
	srv, login := newUserInfoServer(t)
	bearer := login([]string{"openid", "profile"})
	out := fetchUserInfo(t, srv, bearer)
	if out["name"] != "Alice Liddell" {
		t.Errorf("name = %v", out["name"])
	}
	for _, k := range []string{"given_name", "family_name", "picture", "preferred_username"} {
		if out[k] == nil {
			t.Errorf("profile claim %q missing", k)
		}
	}
	// Email absent without email scope.
	if out["email"] != nil {
		t.Errorf("email leaked: %v", out["email"])
	}
}

func TestUserInfo_OIDC_PhoneAndAddressScopes(t *testing.T) {
	srv, login := newUserInfoServer(t)
	bearer := login([]string{"openid", "phone", "address"})
	out := fetchUserInfo(t, srv, bearer)
	if out["phone_number"] != "+15551234567" {
		t.Errorf("phone_number = %v", out["phone_number"])
	}
	if v, ok := out["phone_number_verified"].(bool); !ok || !v {
		t.Errorf("phone_number_verified = %v", out["phone_number_verified"])
	}
	if out["address"] != "Wonderland" {
		t.Errorf("address = %v", out["address"])
	}
}

func TestUserInfo_OIDC_NonStandardFieldsOmitted(t *testing.T) {
	// OIDC profile MUST NOT expose non-standard fields like provider,
	// created_at, custom Attributes outside the scoped allowlist.
	srv, login := newUserInfoServer(t)
	bearer := login([]string{"openid", "email", "profile", "phone", "address"})
	out := fetchUserInfo(t, srv, bearer)
	for _, k := range []string{"provider", "external_id", "created_at", "updated_at", "attributes", "custom_attr"} {
		if out[k] != nil {
			t.Errorf("non-standard field %q leaked: %v", k, out[k])
		}
	}
}

// ---------- legacy path (no openid scope) ----------

func TestUserInfo_LegacyWithoutOpenIDFiltersNonStandardAttributes(t *testing.T) {
	srv, login := newUserInfoServer(t)
	bearer := login([]string{"profile"}) // profile alone, no openid
	out := fetchUserInfo(t, srv, bearer)
	if out["id"] != uiUser {
		t.Errorf("id = %v", out["id"])
	}
	// Legacy shape still returns the User struct fields; "provider" is the
	// User.Provider first-class field set by the upsert path.
	if out["provider"] != "password" {
		t.Errorf("provider not echoed in legacy shape: %v", out)
	}
	// SECURITY: the legacy path now applies the same DEFAULT-DENY claim
	// allowlist to Attributes as the OIDC path, so a non-standard custom_attr
	// is filtered out (and so is any credential/internal key that shares the
	// User.Attributes bag, e.g. password_hash / seeded_password) — closing the
	// credential leak the raw full-user dump caused.
	attrs, _ := out["attributes"].(map[string]any)
	if attrs == nil {
		t.Fatalf("attributes missing in legacy path: %v", out)
	}
	if _, leaked := attrs["custom_attr"]; leaked {
		t.Errorf("non-standard custom_attr leaked on legacy path (default-deny breached): %v", attrs)
	}
	// Releasable standard claims still flow.
	if attrs["given_name"] != "Alice" {
		t.Errorf("releasable standard claim given_name dropped on legacy path: %v", attrs)
	}
}

func TestUserInfo_LegacyNoScopesAtAllAlsoReturnsFullObject(t *testing.T) {
	// scope omitted from login → no scopes on token → not OIDC → legacy.
	srv, login := newUserInfoServer(t)
	bearer := login(nil)
	out := fetchUserInfo(t, srv, bearer)
	if out["attributes"] == nil {
		t.Errorf("expected full-user shape, got OIDC-shaped response: %v", out)
	}
}

// RFC 9068 auth claims passthrough on the OIDC profile: when the
// access token carries auth_time / amr / acr (because login stamped
// them via Subject), /userinfo surfaces them so the RP can reason
// about factor strength without re-validating the access token.

func TestUserInfo_OIDC_AuthTimeAndAMRPassedThrough(t *testing.T) {
	srv, login := newUserInfoServer(t)
	bearer := login([]string{"openid"})
	out := fetchUserInfo(t, srv, bearer)
	// auth_time stamped by handleLogin from time.Now() at the
	// authentication moment.
	authTime, ok := out["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time missing or wrong type: %v", out["auth_time"])
	}
	now := float64(time.Now().Unix())
	if authTime < now-5 || authTime > now+5 {
		t.Errorf("auth_time = %v outside the expected window (now=%v)", authTime, now)
	}
	// amr surfaces the authenticator's RFC 8176 AuthMethods (the password
	// authenticator records "pwd"), not the OAuth provider id "password".
	amr, ok := out["amr"].([]any)
	if !ok {
		t.Fatalf("amr missing or wrong type: %v", out["amr"])
	}
	if len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("amr = %v want [pwd]", amr)
	}
	// acr is omitted because this authenticator reports no AchievedACR;
	// the plumbing exists (see acr_test.go) but this result carries none.
	if _, present := out["acr"]; present {
		t.Errorf("acr should be omitted when the authenticator sets no AchievedACR: %v", out["acr"])
	}
}

func TestUserInfo_OIDC_AbsentWhenNoOpenIDScope(t *testing.T) {
	// Without openid scope, the legacy User-object response path
	// fires. auth_time / amr live only on the OIDC-profile branch
	// — the legacy shape shouldn't accidentally project them
	// (it returns the User struct which has no such fields).
	srv, login := newUserInfoServer(t)
	bearer := login([]string{"email"})
	out := fetchUserInfo(t, srv, bearer)
	if _, present := out["auth_time"]; present {
		t.Errorf("auth_time should not appear on legacy /userinfo: %v", out)
	}
	if _, present := out["amr"]; present {
		t.Errorf("amr should not appear on legacy /userinfo: %v", out)
	}
}
