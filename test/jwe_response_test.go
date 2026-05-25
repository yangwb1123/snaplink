package ssotest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	jweRespUserID   = "u-jwe"
	jweRespClientID = "jwe-resp-client"
	jweRespSecret   = "jwe-secret"
	jweRespPassword = "pw"
)

// jweRespHarness builds a server with response encryption wired and a
// client that registered both id_token and userinfo encryption to the
// supplied RP RSA public key.
func jweRespHarness(t *testing.T, rpPriv *rsa.PrivateKey, withEncrypter bool) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{
		ID: jweRespUserID, Email: "bob@example.com", Name: "Bob",
	})
	pub := &rpPriv.PublicKey
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: jweRespClientID, Secret: jweRespSecret, Active: true,
		AllowedAuthenticators:        []string{"password"},
		TokenStrategy:                "jwt",
		IDTokenEncryptedResponseAlg:  "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc:  "A256GCM",
		UserinfoEncryptedResponseAlg: "RSA-OAEP-256",
		UserinfoEncryptedResponseEnc: "A256GCM",
		JWKS: []sso.JWK{{
			Kty: "RSA", Use: "enc", Kid: "rp-1",
			N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != jweRespPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: jweRespUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withEncrypter {
		opts = append(opts, sso.WithJWEResponseEncrypter(defaultimpl.NewRSAJWEResponseEncrypter()))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func jweLogin(t *testing.T, srv *httptest.Server) (idToken, accessToken string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  jweRespClientID,
		"credential": map[string]string{"username": jweRespUserID, "password": jweRespPassword},
		"scope":      []string{"openid", "email", "profile"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	idToken, _ = out["id_token"].(string)
	accessToken, _ = out["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("no access_token: %s", rb)
	}
	return idToken, accessToken
}

func decryptJWE(t *testing.T, compact string, priv *rsa.PrivateKey) []byte {
	t.Helper()
	obj, err := jose.ParseEncryptedCompact(
		compact,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	if err != nil {
		t.Fatalf("parse jwe: %v", err)
	}
	pt, err := obj.Decrypt(priv)
	if err != nil {
		t.Fatalf("decrypt jwe: %v", err)
	}
	return pt
}

func TestJWEResponse_IDTokenEncrypted(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jweRespHarness(t, priv, true)
	idToken, _ := jweLogin(t, srv)
	if idToken == "" {
		t.Fatal("expected an id_token")
	}
	// Encrypted id_token is a 5-segment JWE.
	if got := strings.Count(idToken, "."); got != 4 {
		t.Fatalf("id_token not a 5-segment JWE (%d dots): %s", got, idToken)
	}
	inner := decryptJWE(t, idToken, priv)
	// Inner is the signed JWS (3 segments).
	if got := strings.Count(string(inner), "."); got != 2 {
		t.Fatalf("inner id_token not a JWS: %s", inner)
	}
}

// TestJWEResponse_IDTokenFailClosed: client opted into encryption but no
// encrypter wired → id_token MUST be omitted (never emitted in clear).
func TestJWEResponse_IDTokenFailClosed(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jweRespHarness(t, priv, false)
	idToken, access := jweLogin(t, srv)
	if access == "" {
		t.Fatal("login should still succeed (id_token issuance is fail-open before encryption)")
	}
	if idToken != "" {
		t.Fatalf("id_token MUST be omitted when encryption requested but unavailable; got %q", idToken)
	}
}

func TestJWEResponse_UserinfoEncrypted(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jweRespHarness(t, priv, true)
	_, access := jweLogin(t, srv)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/jwt" {
		t.Fatalf("Content-Type = %q want application/jwt", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if got := strings.Count(string(body), "."); got != 4 {
		t.Fatalf("userinfo not a 5-segment JWE (%d dots)", got)
	}
	pt := decryptJWE(t, string(body), priv)
	var claims map[string]any
	if err := json.Unmarshal(pt, &claims); err != nil {
		t.Fatalf("inner userinfo not JSON: %v (%s)", err, pt)
	}
	if claims["sub"] == nil {
		t.Fatalf("missing sub in decrypted userinfo: %v", claims)
	}
}

// TestJWEResponse_UserinfoFailClosed: encryption requested but no
// encrypter wired → server_error, never cleartext JSON.
func TestJWEResponse_UserinfoFailClosed(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jweRespHarness(t, priv, false)
	_, access := jweLogin(t, srv)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d want 500", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/jwt") {
		t.Fatal("must not emit a JWT when fail-closed")
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "server_error" {
		t.Fatalf("error = %v want server_error", body["error"])
	}
}
