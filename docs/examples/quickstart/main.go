// Command quickstart is a complete, self-contained, runnable end-to-end demo of
// the snaplink SSO server. It embeds the server as a Go library (the SDK
// surface), serves it on an ephemeral loopback port, then drives a full
// OAuth 2.0 Authorization Code + PKCE flow over HTTP -- discovery, login, code
// exchange, userinfo -- and finally verifies the issued JWT LOCALLY against the
// server's JWKS using the remote consumer client (no server round-trip).
//
// Run it (no config file, no external dependencies, everything in-memory):
//
//	go run ./docs/examples/quickstart
//
// Demo identity: user "alice"/"s3cret", confidential client "demo-app".
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
)

const (
	demoUserID   = "user-alice"
	demoUsername = "alice"
	demoPassword = "s3cret"
	demoClientID = "demo-app"
	demoSecret   = "demo-secret"
	demoRedirect = "https://app.example.com/callback"
	// A fixed RFC 7636 code_verifier (>= 43 chars). A real client generates a
	// fresh random one per authorization request.
	pkceVerifier = "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"
)

func main() {
	log.SetFlags(0)
	base := startServer()
	fmt.Printf("snaplink SSO quickstart -- in-memory server at %s\n\n", base)

	disco := discover(base)
	fmt.Printf("[1] discovery   issuer=%v\n                token=%v\n                userinfo=%v\n                jwks=%v\n\n",
		disco["issuer"], disco["token_endpoint"], disco["userinfo_endpoint"], disco["jwks_uri"])

	code := loginForCode(base)
	fmt.Printf("[2] login       authorization_code + PKCE -> code=%s\n\n", short(code))

	tokens := exchangeCode(base, code)
	access := tokens["access_token"].(string)
	fmt.Printf("[3] token       access_token=%s\n                id_token=%s\n\n",
		short(access), short(fmt.Sprint(tokens["id_token"])))

	fmt.Printf("[4] userinfo    %v\n\n", userInfo(base, access))

	subj := verifyLocally(fmt.Sprint(disco["jwks_uri"]), access)
	fmt.Printf("[5] local verify (signature checked against cached JWKS, no server call)\n                subject=%s  scopes=%v\n\n", subj.ID, subj.Scopes)

	fmt.Println("OK -- end-to-end OAuth2/OIDC flow complete.")
}

// startServer wires an in-memory SSO server via the SDK options and serves its
// http.Handler on a random loopback port, returning the base URL. This is the
// "embed the SSO as a library" surface; swap the memory backends for
// infrastructure/defaultimpl/sqlite (or your own implementations) in production.
func startServer() string {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: demoUserID})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    demoClientID,
		Secret:                demoSecret,
		Name:                  "Demo App",
		RedirectURIs:          []string{demoRedirect},
		AllowedScopes:         []string{"openid", "profile", "email"},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	// One Ed25519 issuer serves both the access-token strategy AND the OIDC
	// id_token (Ed25519JWTIssuer satisfies oidc.IDTokenIssuer), so /token mints
	// an id_token whenever the request carries the openid scope.
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(passwordAuth()),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		// Wiring an auth-code store ENABLES the authorization_code grant + /token.
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	go func() { _ = http.Serve(ln, srv.Handler()) }()
	return "http://" + ln.Addr().String()
}

// passwordAuth is a trivial username/password Authenticator. A real one verifies
// against your user store (the bundled bcrypt password authenticator does this);
// here we hardcode the demo credential.
func passwordAuth() sso.Authenticator {
	return authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, user, pass string) (*sso.AuthResult, error) {
			if user == demoUsername && pass == demoPassword {
				return &sso.AuthResult{UserID: demoUserID, ExternalID: user}, nil
			}
			return nil, errors.New("invalid credentials")
		}))
}

// discover fetches the OIDC discovery document -- the entry point a remote RP
// uses to learn every endpoint + supported algorithm.
func discover(base string) map[string]any {
	resp, err := http.Get(base + "/.well-known/openid-configuration")
	if err != nil {
		log.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return decodeJSON(resp.Body)
}

// loginForCode drives POST /auth/login with response_type=code + the PKCE
// challenge, returning the one-time authorization code.
func loginForCode(base string) string {
	body := postJSON(base+"/auth/login", map[string]any{
		"provider":              "password",
		"client_id":             demoClientID,
		"credential":            map[string]string{"username": demoUsername, "password": demoPassword},
		"response_type":         "code",
		"redirect_uri":          demoRedirect,
		"scope":                 []string{"openid", "profile", "email"},
		"code_challenge":        s256(pkceVerifier),
		"code_challenge_method": "S256",
	})
	code, _ := body["code"].(string)
	if code == "" {
		log.Fatalf("login returned no code: %v", body)
	}
	return code
}

// exchangeCode redeems the code at POST /token (grant_type=authorization_code)
// presenting the PKCE verifier + client credentials.
func exchangeCode(base, code string) map[string]any {
	body := postJSON(base+"/token", map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     demoClientID,
		"client_secret": demoSecret,
		"redirect_uri":  demoRedirect,
		"code_verifier": pkceVerifier,
	})
	if body["access_token"] == nil {
		log.Fatalf("token exchange failed: %v", body)
	}
	return body
}

// userInfo calls GET /userinfo with the bearer access token.
func userInfo(base, accessToken string) map[string]any {
	req, _ := http.NewRequest(http.MethodGet, base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return decodeJSON(resp.Body)
}

// verifyLocally is the remote-consumer pattern: a downstream service validates
// the JWT signature itself against the SSO server's cached JWKS, so the SSO is
// not on the per-request hot path. Returns the resolved subject.
func verifyLocally(jwksURI, accessToken string) *ssoclient.Subject {
	jwks := remote.NewJWKSCache(jwksURI)
	defer jwks.Close()
	// The demo issuer mints iss = sso.DefaultIssuer (no WithEd25519Issuer),
	// so the pin is the issuer constant, NOT the discovery document's
	// issuer — that value is request-base-derived here and would mismatch.
	// A real deployment pins its configured AS issuer.
	subj, err := remote.NewAuthClient(jwks, remote.WithIssuer(sso.DefaultIssuer)).ValidateToken(context.Background(), accessToken)
	if err != nil {
		log.Fatalf("local token verify: %v", err)
	}
	return subj
}

// --- tiny HTTP/JSON helpers ---

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func postJSON(url string, payload map[string]any) map[string]any {
	raw, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		log.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return decodeJSON(resp.Body)
}

func decodeJSON(r io.Reader) map[string]any {
	out := map[string]any{}
	_ = json.NewDecoder(r).Decode(&out)
	return out
}

func short(s string) string {
	const max = 18
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
