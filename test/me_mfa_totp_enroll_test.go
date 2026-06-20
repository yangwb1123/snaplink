package ssotest

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// totpNow computes the current 6-digit TOTP for secret — a self-contained
// RFC 6238 reimplementation so the integration test can drive the enrollment
// confirm leg without reaching into the authenticators package internals.
func totpNow(secret []byte) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(time.Now().Unix()/30))
	m := hmac.New(sha1.New, secret)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | (uint32(sum[off+1])&0xff)<<16 |
		(uint32(sum[off+2])&0xff)<<8 | uint32(sum[off+3])&0xff
	return fmt.Sprintf("%06d", bin%1000000)
}

func decodeB32(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatalf("decode base32 secret %q: %v", s, err)
	}
	return b
}

// newTOTPEnrollHarness wires a server whose ONE MemoryTOTPEnrollmentStore backs
// both the TOTP authenticator's secret reads and self-service /me/mfa, with an
// optional TOTP enroller (the gate for the begin/confirm routes).
func newTOTPEnrollHarness(t *testing.T, withEnroller bool) (*httptest.Server, func() string, *defaultimpl.MemoryTOTPEnrollmentStore) {
	t.Helper()
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("totp-enroll-test"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-alice"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "totp-app", Secret: "s", Name: "TOTP App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u-alice"}, nil
		},
	))
	store := defaultimpl.NewMemoryTOTPEnrollmentStore()
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithMFAEnrollmentStore(store),
	}
	if withEnroller {
		opts = append(opts, sso.WithTOTPEnroller(authenticators.NewTOTPEnroller(authenticators.NewTOTPAuthenticator(store))))
	}
	server := sso.NewServer(opts...)
	hs := httptest.NewServer(server.Handler())
	t.Cleanup(hs.Close)

	loginAs := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider": "password", "client_id": "totp-app",
			"credential": map[string]string{"username": "alice", "password": "pw"},
		})
		resp, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("login: no token: %v", out)
		}
		return tok
	}
	return hs, loginAs, store
}

// totpPost POSTs an optional JSON body with an optional bearer.
func totpPost(t *testing.T, url, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(http.MethodPost, url, rdr)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestTOTPEnroll_Begin(t *testing.T) {
	srv, loginAs, _ := newTOTPEnrollHarness(t, true)
	tok := loginAs()
	code, body := totpPost(t, srv.URL+"/me/mfa/totp/begin", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, body)
	}
	if s, _ := body["secret"].(string); s == "" {
		t.Errorf("begin returned no secret: %v", body)
	}
	uri, _ := body["otpauth_uri"].(string)
	if len(uri) < len("otpauth://totp/") || uri[:len("otpauth://totp/")] != "otpauth://totp/" {
		t.Errorf("otpauth_uri = %q, want otpauth://totp/ prefix", uri)
	}
}

func TestTOTPEnroll_ConfirmThenListedAndUsable(t *testing.T) {
	srv, loginAs, store := newTOTPEnrollHarness(t, true)
	tok := loginAs()

	_, begin := totpPost(t, srv.URL+"/me/mfa/totp/begin", tok, nil)
	secretB32, _ := begin["secret"].(string)
	secret := decodeB32(t, secretB32)

	code, body := totpPost(t, srv.URL+"/me/mfa/totp/confirm", tok, map[string]any{
		"secret": secretB32, "code": totpNow(secret), "label": "Phone",
	})
	if code != http.StatusCreated {
		t.Fatalf("confirm status=%d body=%v", code, body)
	}
	if fid, _ := body["factor_id"].(string); fid == "" {
		t.Errorf("confirm returned no factor_id: %v", body)
	}

	// The factor is now listed by GET /me/mfa.
	lc, list := doReq(t, srv, http.MethodGet, "/me/mfa", tok)
	if lc != http.StatusOK {
		t.Fatalf("list status=%d", lc)
	}
	factors, _ := list["factors"].([]any)
	if len(factors) != 1 {
		t.Fatalf("want 1 factor after enroll, got %v", list)
	}
	f0, _ := factors[0].(map[string]any)
	if f0["method"] != "totp" || f0["label"] != "Phone" {
		t.Errorf("factor = %v, want method=totp label=Phone", f0)
	}

	// The secret is usable by the login-time verifier (same store).
	got, err := store.GetSecret(context.Background(), "u-alice")
	if err != nil || string(got) != string(secret) {
		t.Errorf("GetSecret after enroll = %q,%v; want the enrolled secret", got, err)
	}
}

func TestTOTPEnroll_WrongCodeIsOracleSafe(t *testing.T) {
	srv, loginAs, _ := newTOTPEnrollHarness(t, true)
	tok := loginAs()
	_, begin := totpPost(t, srv.URL+"/me/mfa/totp/begin", tok, nil)
	secretB32, _ := begin["secret"].(string)

	code, body := totpPost(t, srv.URL+"/me/mfa/totp/confirm", tok, map[string]any{
		"secret": secretB32, "code": "000000",
	})
	if code != http.StatusBadRequest || body["error"] != "totp_invalid_code" {
		t.Fatalf("status=%d body=%v, want 400 totp_invalid_code", code, body)
	}
}

func TestTOTPEnroll_BadSecretIsOracleSafe(t *testing.T) {
	// A malformed secret collapses to the SAME response as a wrong code.
	srv, loginAs, _ := newTOTPEnrollHarness(t, true)
	tok := loginAs()
	code, body := totpPost(t, srv.URL+"/me/mfa/totp/confirm", tok, map[string]any{
		"secret": "not-valid-base32-!!!", "code": "123456",
	})
	if code != http.StatusBadRequest || body["error"] != "totp_invalid_code" {
		t.Fatalf("status=%d body=%v, want 400 totp_invalid_code", code, body)
	}
}

func TestTOTPEnroll_RequiresBearer(t *testing.T) {
	srv, _, _ := newTOTPEnrollHarness(t, true)
	if code, _ := totpPost(t, srv.URL+"/me/mfa/totp/begin", "", nil); code != http.StatusUnauthorized {
		t.Errorf("begin without bearer = %d, want 401", code)
	}
}

func TestTOTPEnroll_NotMountedWithoutEnroller(t *testing.T) {
	// The store IS a TOTPEnrollmentWriter, but no enroller is wired → routes
	// are not mounted (byte-identical off).
	srv, loginAs, _ := newTOTPEnrollHarness(t, false)
	tok := loginAs()
	if code, _ := totpPost(t, srv.URL+"/me/mfa/totp/begin", tok, nil); code != http.StatusNotFound {
		t.Errorf("begin without enroller = %d, want 404 (route unmounted)", code)
	}
}

func TestTOTPEnroll_NotMountedWithoutWriter(t *testing.T) {
	// An enroller is wired but the MFAEnrollmentStore is a plain store that is
	// NOT a TOTPEnrollmentWriter → routes are not mounted.
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "c", Secret: "s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithMFAEnrollmentStore(defaultimpl.NewMemoryMFAEnrollmentStore()),
		sso.WithTOTPEnroller(authenticators.NewTOTPEnroller(authenticators.NewTOTPAuthenticator(authenticators.NewMemoryTOTPStore()))),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	resp, err := http.Post(hs.URL+"/me/mfa/totp/begin", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d, want 404 (route unmounted without a writer)", resp.StatusCode)
	}
}
