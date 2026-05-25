package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	jarmUserID   = "u-jarm"
	jarmClientID = "jarm-client"
	jarmSecret   = "jarm-secret"
	jarmPassword = "pw"
	jarmRedirect = "https://app.example/cb"
)

// newJARMHarness builds a server with JARM wired (shared Ed25519
// signer for tokens + JARM). withJARM=false omits WithJARM so the
// fail-closed path can be exercised.
func newJARMHarness(t *testing.T, withJARM bool) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: jarmUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: jarmClientID, Secret: jarmSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{jarmRedirect},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != jarmPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: jarmUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	}
	if withJARM {
		opts = append(opts, sso.WithJARM(issuer))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func jarmLogin(t *testing.T, srv *httptest.Server, mode string) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     jarmClientID,
		"credential":    map[string]string{"username": jarmUserID, "password": jarmPassword},
		"response_type": "code",
		"redirect_uri":  jarmRedirect,
		"state":         "jarm-state",
		"response_mode": mode,
	})
	// Don't follow the JARM redirect — we inspect the Location header.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return resp
}

func TestJARM_QueryDeliverySignedResponse(t *testing.T) {
	srv := newJARMHarness(t, true)
	for _, mode := range []string{"jwt", "query.jwt"} {
		resp := jarmLogin(t, srv, mode)
		if resp.StatusCode != http.StatusFound {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("mode=%s status=%d body=%s", mode, resp.StatusCode, raw)
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		resp.Body.Close()
		if err != nil {
			t.Fatalf("mode=%s parse Location: %v", mode, err)
		}
		jwt := loc.Query().Get("response")
		if jwt == "" {
			t.Fatalf("mode=%s missing response param: %q", mode, resp.Header.Get("Location"))
		}
		if len(strings.Split(jwt, ".")) != 3 {
			t.Errorf("mode=%s response is not a JWS: %q", mode, jwt)
		}
		// No bare code/state leaked alongside the signed response.
		if loc.Query().Get("code") != "" {
			t.Errorf("mode=%s bare code leaked alongside JARM response", mode)
		}
	}
}

func TestJARM_FragmentDelivery(t *testing.T) {
	srv := newJARMHarness(t, true)
	resp := jarmLogin(t, srv, "fragment.jwt")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Location"), "#response=") {
		t.Errorf("fragment delivery must carry #response=, got %q", resp.Header.Get("Location"))
	}
}

func TestJARM_FormPostDelivery(t *testing.T) {
	srv := newJARMHarness(t, true)
	resp := jarmLogin(t, srv, "form_post.jwt")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), `name="response"`) {
		t.Errorf("form_post.jwt body missing response field: %s", raw)
	}
}

func TestJARM_FailsClosedWithoutSigner(t *testing.T) {
	// response_mode=jwt without WithJARM wired → invalid_request
	// (fail-closed; never degrade to an unsigned response).
	srv := newJARMHarness(t, false)
	resp := jarmLogin(t, srv, "jwt")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["error"] != sso.ErrInvalidRequest {
		t.Errorf("error=%v want %q", out["error"], sso.ErrInvalidRequest)
	}
}

func TestJARM_DiscoveryAdvertisesWhenWired(t *testing.T) {
	srv := newJARMHarness(t, true)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)

	modes, _ := doc["response_modes_supported"].([]any)
	if !containsAny(modes, "jwt") {
		t.Errorf("response_modes_supported = %v, want to contain jwt", modes)
	}
	algs, _ := doc["authorization_signing_alg_values_supported"].([]any)
	if !containsAny(algs, "EdDSA") {
		t.Errorf("authorization_signing_alg_values_supported = %v, want EdDSA", algs)
	}
}

func TestJARM_DiscoveryOmitsWhenUnwired(t *testing.T) {
	srv := newJARMHarness(t, false)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if _, ok := doc["authorization_signing_alg_values_supported"]; ok {
		t.Error("authorization_signing_alg_values_supported must be absent without JARM")
	}
	modes, _ := doc["response_modes_supported"].([]any)
	if containsAny(modes, "jwt") {
		t.Errorf("jwt response mode advertised without JARM wired: %v", modes)
	}
}

func containsAny(xs []any, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
