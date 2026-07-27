package ssotest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

// These tests pin two CIBA token-grant defects:
//
// Bug 1: the refresh-token first-issue call passed r.Nonce in the familyID
//        position, so an RP-supplied OIDC nonce became the refresh family key —
//        low entropy + RP-controlled, enabling a cross-flow DeleteFamily DoS.
// Bug 2: the id_token was assigned directly to the response WITHOUT routing
//        through maybeEncryptIDToken, so a client with
//        IDTokenEncryptedResponseAlg got cleartext instead of a JWE.

const (
	cibaHardClient = "ciba-hard-client"
	cibaHardSecret = "ciba-hard-secret"
	cibaHardUser   = "u-ciba-hard"
	cibaHardNonce  = "rp-supplied-nonce-xyz"
)

// driveCIBAToToken runs a full poll flow to a successful token response and
// returns the decoded body. The client is seeded by the caller so each test
// can vary its encryption attributes.
func driveCIBAToToken(t *testing.T, srv *httptest.Server, store oauth.CIBAStore, nonce string) map[string]any {
	t.Helper()
	form := url.Values{}
	form.Set("login_hint", cibaHardUser)
	form.Set("scope", "openid profile")
	form.Set("nonce", nonce)
	form.Set("client_id", cibaHardClient)
	form.Set("client_secret", cibaHardSecret)
	resp, err := http.Post(srv.URL+"/backchannel-authentication",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("backchannel auth: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var auth map[string]any
	_ = json.Unmarshal(raw, &auth)
	authReqID, _ := auth["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("no auth_req_id: %s", raw)
	}
	if err := store.SetStatus(context.Background(), authReqID, oauth.CIBAApproved); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	pollForm := url.Values{}
	pollForm.Set("grant_type", oauth.GrantCIBA)
	pollForm.Set("auth_req_id", authReqID)
	pollForm.Set("client_id", cibaHardClient)
	pollForm.Set("client_secret", cibaHardSecret)
	pr, err := http.Post(srv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(pollForm.Encode()))
	if err != nil {
		t.Fatalf("token poll: %v", err)
	}
	praw, _ := io.ReadAll(pr.Body)
	_ = pr.Body.Close()
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("token poll status=%d body=%s", pr.StatusCode, praw)
	}
	var out map[string]any
	_ = json.Unmarshal(praw, &out)
	return out
}

// TestCIBA_RefreshFamilyIDIsNotNonce proves the issued refresh token's family
// id is a fresh high-entropy value, NOT the RP-supplied OIDC nonce (Bug 1).
func TestCIBA_RefreshFamilyIDIsNotNonce(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: cibaHardUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: cibaHardClient, Secret: cibaHardSecret, Active: true,
		TokenStrategy: "jwt",
	})
	store := defaultimpl.NewMemoryCIBAStore()
	refresh := defaultimpl.NewMemoryRefreshTokenStore()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	transport := oauth.CIBATransportFunc(func(context.Context, string, string, map[string]string) error { return nil })

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(refresh, time.Hour),
		sso.WithCIBA(store, transport, 2*time.Minute, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	out := driveCIBAToToken(t, httpSrv, store, cibaHardNonce)
	rt, _ := out["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh_token in CIBA response: %v", out)
	}

	entry, err := refresh.Inspect(context.Background(), rt)
	if err != nil {
		t.Fatalf("inspect refresh token: %v", err)
	}
	if entry.FamilyID == cibaHardNonce {
		t.Fatal("CIBA refresh FamilyID is the RP-supplied nonce (Bug 1) — must be a fresh random family id")
	}
	if entry.FamilyID == "" {
		t.Fatal("CIBA refresh FamilyID is empty — family rotation defense disabled")
	}
	// First-issue mints a 32-byte (256-bit) base64url family id, same generator
	// as the token; the nonce here is far shorter. Guard against any accidental
	// low-entropy value sneaking back in.
	if len(entry.FamilyID) < 40 {
		t.Fatalf("CIBA refresh FamilyID %q looks low-entropy (len %d); want a 256-bit token", entry.FamilyID, len(entry.FamilyID))
	}
}

// TestCIBA_IDTokenEncryptedWhenClientOptsIn proves the CIBA id_token is routed
// through the JWE encrypter for a client that registered
// IDTokenEncryptedResponseAlg, instead of leaking cleartext (Bug 2).
func TestCIBA_IDTokenEncryptedWhenClientOptsIn(t *testing.T) {
	rpPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &rpPriv.PublicKey

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: cibaHardUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: cibaHardClient, Secret: cibaHardSecret, Active: true,
		TokenStrategy:               "jwt",
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
		JWKS: []sso.JWK{{
			Kty: "RSA", Use: "enc", Kid: "rp-1",
			N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
	store := defaultimpl.NewMemoryCIBAStore()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	transport := oauth.CIBATransportFunc(func(context.Context, string, string, map[string]string) error { return nil })

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithJWEResponseEncrypter(defaultimpl.NewRSAJWEResponseEncrypter()),
		sso.WithCIBA(store, transport, 2*time.Minute, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	out := driveCIBAToToken(t, httpSrv, store, cibaHardNonce)
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in CIBA response: %v", out)
	}
	// An encrypted id_token is a 5-segment (4-dot) JWE; cleartext is a 3-segment
	// JWS. Pre-fix this was the cleartext JWS.
	if got := strings.Count(idToken, "."); got != 4 {
		t.Fatalf("CIBA id_token not a JWE (%d dots) — cleartext leak (Bug 2): %s", got, idToken)
	}
	inner := decryptJWE(t, idToken, rpPriv)
	if got := strings.Count(string(inner), "."); got != 2 {
		t.Fatalf("decrypted CIBA id_token inner is not a signed JWS: %s", inner)
	}
}
