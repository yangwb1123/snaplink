package ssotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// TestMultiAlg_RSAIssuer_EndToEnd wires the real RSAJWTIssuer as the JWT
// token + id_token issuer and proves the full server path: login mints an
// RS256-signed access token, the server validates it across issuers via
// /token/introspect, and /.well-known/jwks.json publishes the RSA key.
func TestMultiAlg_RSAIssuer_EndToEnd(t *testing.T) {
	for _, alg := range []string{"RS256", "PS256"} {
		t.Run(alg, func(t *testing.T) {
			const clientID, userID, secret, pw = "rsa-client", "u-rsa", "s3cr3t", "pw"
			users := defaultimpl.NewMemoryUserProvider()
			_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: userID, Name: "R"})
			clients := defaultimpl.NewMemoryClientStore()
			clients.AddSeed(&sso.Client{
				ID: clientID, Secret: secret, Active: true,
				AllowedAuthenticators: []string{"password"},
				TokenStrategy:         "jwt",
			})
			pwAuth := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
				func(_ context.Context, _, p string) (*sso.AuthResult, error) {
					if p != pw {
						return nil, errPW
					}
					return &sso.AuthResult{UserID: userID, Provider: "password"}, nil
				},
			))
			rsaIss := defaultimpl.NewRSAJWTIssuer(
				defaultimpl.WithRSAIssuer("rsa-test"),
				defaultimpl.WithRSAAlg(alg),
				defaultimpl.WithRSATokenTTL(5*time.Minute),
			)
			srv := sso.NewServer(
				sso.WithRouter(sso.NewStdRouter()),
				sso.WithUserProvider(users),
				sso.WithClientStore(clients),
				sso.WithAuthenticator(pwAuth),
				sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
				sso.WithTokenIssuer("jwt", rsaIss),
				sso.WithIDTokenIssuer(rsaIss),
				sso.WithDefaultTokenStrategy("jwt"),
				sso.WithSupportedSigningAlgs(alg),
			)
			ts := httptest.NewServer(srv.Handler())
			t.Cleanup(ts.Close)

			// JWKS publishes the RSA key.
			jr, err := http.Get(ts.URL + "/.well-known/jwks.json")
			if err != nil {
				t.Fatal(err)
			}
			var jwks struct {
				Keys []map[string]any `json:"keys"`
			}
			_ = json.NewDecoder(jr.Body).Decode(&jwks)
			_ = jr.Body.Close()
			if len(jwks.Keys) == 0 || jwks.Keys[0]["kty"] != "RSA" {
				t.Fatalf("JWKS missing RSA key: %v", jwks.Keys)
			}

			// Login mints an RS256/PS256-signed access token.
			body, _ := json.Marshal(map[string]any{
				"provider":   "password",
				"client_id":  clientID,
				"credential": map[string]string{"username": userID, "password": pw},
				"scope":      []string{"openid"},
			})
			lr, err := http.Post(ts.URL+"/auth/login", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			lb, _ := io.ReadAll(lr.Body)
			_ = lr.Body.Close()
			var login map[string]any
			_ = json.Unmarshal(lb, &login)
			at, _ := login["access_token"].(string)
			if at == "" {
				t.Fatalf("no access_token: %s", lb)
			}
			hb, _ := base64.RawURLEncoding.DecodeString(strings.SplitN(at, ".", 2)[0])
			var hdr map[string]any
			_ = json.Unmarshal(hb, &hdr)
			if hdr["alg"] != alg {
				t.Errorf("access token alg = %v, want %s", hdr["alg"], alg)
			}

			// The server validates its own RSA token via introspection.
			form := "token=" + at
			ir, _ := http.NewRequest(http.MethodPost, ts.URL+"/token/introspect", strings.NewReader(form))
			ir.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			ir.SetBasicAuth(clientID, secret)
			iresp, err := http.DefaultClient.Do(ir)
			if err != nil {
				t.Fatal(err)
			}
			ib, _ := io.ReadAll(iresp.Body)
			_ = iresp.Body.Close()
			var intro map[string]any
			_ = json.Unmarshal(ib, &intro)
			if intro["active"] != true {
				t.Errorf("introspect active = %v, want true (server failed to validate its own %s token): %s", intro["active"], alg, ib)
			}
		})
	}
}
