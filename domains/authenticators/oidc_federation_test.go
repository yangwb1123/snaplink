package authenticators

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// fakeIdP boots an httptest.Server that pretends to be Google /
// Microsoft / generic-OIDC. Token endpoint expects Basic auth, code,
// + grant_type=authorization_code; userinfo endpoint expects the
// access token as Bearer.
type fakeIdP struct {
	t                  *testing.T
	srv                *httptest.Server
	expectedCode       string
	expectedClient     string
	expectedSecret     string
	tokenStatus        int
	userinfoStatus     int
	tokenResponse      map[string]any
	userinfoResponse   map[string]any
	tokenRequests      int
	userinfoRequests   int
	lastTokenForm      url.Values
	lastUserinfoBearer string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{
		t:              t,
		expectedCode:   "valid-code",
		expectedClient: "demo-rp",
		expectedSecret: "demo-secret",
		tokenStatus:    200,
		userinfoStatus: 200,
		tokenResponse: map[string]any{
			"access_token": "upstream-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		},
		userinfoResponse: map[string]any{
			"sub":            "alice@example.com",
			"email":          "alice@example.com",
			"name":           "Alice Example",
			"email_verified": true,
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", f.handleToken)
	mux.HandleFunc("/userinfo", f.handleUserinfo)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	f.tokenRequests++
	cid, secret, ok := r.BasicAuth()
	if !ok || cid != f.expectedClient || secret != f.expectedSecret {
		http.Error(w, "bad client auth", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	f.lastTokenForm = form
	if form.Get("code") != f.expectedCode {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	if f.tokenStatus != 200 {
		w.WriteHeader(f.tokenStatus)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(f.tokenResponse)
}

func (f *fakeIdP) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	f.userinfoRequests++
	f.lastUserinfoBearer = r.Header.Get("Authorization")
	if f.userinfoStatus != 200 {
		w.WriteHeader(f.userinfoStatus)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(f.userinfoResponse)
}

func newOIDCFedForTest(t *testing.T, idp *fakeIdP) *OIDCFederationAuthenticator {
	t.Helper()
	auth, err := NewOIDCFederationAuthenticator(OIDCFederationConfig{
		Name:                  "test-idp",
		AuthorizationEndpoint: idp.srv.URL + "/authorize",
		TokenEndpoint:         idp.srv.URL + "/token",
		UserinfoEndpoint:      idp.srv.URL + "/userinfo",
		ClientID:              idp.expectedClient,
		ClientSecret:          idp.expectedSecret,
		RedirectURI:           "https://as.example/callback",
		Scopes:                []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("NewOIDCFederationAuthenticator: %v", err)
	}
	return auth
}

func TestOIDCFederation_LoginURLBuildsAuthorizeURL(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	auth := newOIDCFedForTest(t, idp)

	got := auth.LoginURL("state-abc")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("LoginURL not a URL: %v", err)
	}
	if !strings.HasSuffix(u.Path, "/authorize") {
		t.Fatalf("LoginURL path = %q, want /authorize", u.Path)
	}
	q := u.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q want code", q.Get("response_type"))
	}
	if q.Get("client_id") != idp.expectedClient {
		t.Errorf("client_id = %q want %q", q.Get("client_id"), idp.expectedClient)
	}
	if q.Get("redirect_uri") != "https://as.example/callback" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if q.Get("state") != "state-abc" {
		t.Errorf("state passthrough broken: %q", q.Get("state"))
	}
	if q.Get("scope") != "openid profile email" {
		t.Errorf("scope = %q", q.Get("scope"))
	}
}

func TestOIDCFederation_LoginURLPreservesPreExistingQuery(t *testing.T) {
	t.Parallel()
	// Some IdPs (Microsoft Azure AD) embed a tenant id in the
	// authorization endpoint path with a trailing ? for global params.
	auth, _ := NewOIDCFederationAuthenticator(OIDCFederationConfig{
		Name:                  "azure",
		AuthorizationEndpoint: "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?prompt=consent",
		TokenEndpoint:         "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
		ClientID:              "x",
		ClientSecret:          "y",
		RedirectURI:           "https://as.example/cb",
	})
	got := auth.LoginURL("state-1")
	if !strings.Contains(got, "prompt=consent") {
		t.Fatalf("pre-existing query lost: %q", got)
	}
	if !strings.Contains(got, "state=state-1") {
		t.Fatalf("state lost: %q", got)
	}
}

func TestOIDCFederation_AuthenticateRejectsDirect(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	auth := newOIDCFedForTest(t, idp)

	_, err := auth.Authenticate(context.Background(), &sso.AuthRequest{
		Credential: map[string]string{"username": "alice", "password": "doesnt-matter"},
	})
	if !errors.Is(err, ErrOIDCFederationDirectAuthUnsupported) {
		t.Fatalf("got %v, want ErrOIDCFederationDirectAuthUnsupported", err)
	}
}

func TestOIDCFederation_CallbackHappyPath(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	auth := newOIDCFedForTest(t, idp)

	result, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "state-abc",
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if result.UserID != "alice@example.com" || result.ExternalID != "alice@example.com" {
		t.Fatalf("subject not mapped: %#v", result)
	}
	if result.Provider != "test-idp" {
		t.Fatalf("provider = %q", result.Provider)
	}
	if result.Attributes["email"] != "alice@example.com" {
		t.Fatalf("attributes lost: %#v", result.Attributes)
	}
	if result.Attributes["name"] != "Alice Example" {
		t.Fatalf("name attribute lost: %v", result.Attributes)
	}
	if len(result.AuthMethods) != 1 || result.AuthMethods[0] != AuthMethodFed {
		t.Fatalf("AuthMethods = %v, want [fed]", result.AuthMethods)
	}
	if idp.tokenRequests != 1 {
		t.Fatalf("token endpoint hit %d times want 1", idp.tokenRequests)
	}
	if idp.userinfoRequests != 1 {
		t.Fatalf("userinfo endpoint hit %d times want 1", idp.userinfoRequests)
	}
	if idp.lastTokenForm.Get("grant_type") != "authorization_code" {
		t.Errorf("token form grant_type = %q", idp.lastTokenForm.Get("grant_type"))
	}
	if idp.lastTokenForm.Get("redirect_uri") != "https://as.example/callback" {
		t.Errorf("token form redirect_uri = %q", idp.lastTokenForm.Get("redirect_uri"))
	}
	if idp.lastUserinfoBearer != "Bearer upstream-access-token" {
		t.Errorf("userinfo bearer = %q", idp.lastUserinfoBearer)
	}
}

func TestOIDCFederation_CallbackEmptyCodeRejected(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	auth := newOIDCFedForTest(t, idp)

	_, err := auth.Callback(context.Background(), &sso.CallbackState{State: "state-abc"})
	if err == nil {
		t.Fatal("empty code must be rejected")
	}
}

func TestOIDCFederation_CallbackPropagatesTokenEndpoint5xx(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	idp.tokenStatus = http.StatusInternalServerError
	auth := newOIDCFedForTest(t, idp)

	_, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if err == nil {
		t.Fatal("expected error on token endpoint 5xx")
	}
}

func TestOIDCFederation_CallbackPropagatesUserinfo5xx(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	idp.userinfoStatus = http.StatusInternalServerError
	auth := newOIDCFedForTest(t, idp)

	_, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if err == nil {
		t.Fatal("expected error on userinfo 5xx")
	}
}

func TestOIDCFederation_NoUserinfoEndpointSkipsLookup(t *testing.T) {
	t.Parallel()
	// Some non-OIDC OAuth providers (GitHub) only return tokens —
	// configuring without UserinfoEndpoint should still fail
	// because the token response carries no `sub`; the error is
	// the wrong-shape "userinfo missing sub" rather than a network
	// error, signaling the misconfig clearly.
	idp := newFakeIdP(t)
	auth, _ := NewOIDCFederationAuthenticator(OIDCFederationConfig{
		Name:                  "no-userinfo",
		AuthorizationEndpoint: idp.srv.URL + "/authorize",
		TokenEndpoint:         idp.srv.URL + "/token",
		ClientID:              idp.expectedClient,
		ClientSecret:          idp.expectedSecret,
		RedirectURI:           "https://as.example/cb",
	})
	_, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if err == nil {
		t.Fatal("expected error when userinfo missing and token response has no sub")
	}
	if idp.userinfoRequests != 0 {
		t.Fatalf("userinfo hit %d times despite empty endpoint", idp.userinfoRequests)
	}
}

func TestOIDCFederation_SubjectFieldOverride(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	idp.userinfoResponse = map[string]any{
		"email":          "bob@example.com",
		"name":           "Bob",
		"email_verified": true,
		// No "sub" — pre-OIDC GitHub-style provider.
	}
	auth, _ := NewOIDCFederationAuthenticator(OIDCFederationConfig{
		Name:                  "github-style",
		AuthorizationEndpoint: idp.srv.URL + "/authorize",
		TokenEndpoint:         idp.srv.URL + "/token",
		UserinfoEndpoint:      idp.srv.URL + "/userinfo",
		ClientID:              idp.expectedClient,
		ClientSecret:          idp.expectedSecret,
		RedirectURI:           "https://as.example/cb",
		SubjectFieldOverride:  "email",
	})
	result, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if result.UserID != "bob@example.com" {
		t.Fatalf("subject field override failed: got %q want bob@example.com", result.UserID)
	}
}

// fakeLinker is a real (non-mock) test double satisfying the UserLinker
// shape directly — small enough that a hand-written implementation, not a
// generated mock, is the natural choice (AGENTS.md: no mocks where a real
// implementation is simple).
type fakeLinker struct {
	gotProvider, gotSubject string
	userID                  string
	err                     error
}

func (f *fakeLinker) ResolveUserID(_ context.Context, provider, subject string) (string, error) {
	f.gotProvider, f.gotSubject = provider, subject
	if f.err != nil {
		return "", f.err
	}
	return f.userID, nil
}

func TestOIDCFederation_NilLinkerIsByteIdenticalToNoLinker(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	// No WithUserLinker option passed at all — must behave exactly like
	// today, i.e. UserID defaults to the raw external subject.
	auth := newOIDCFedForTest(t, idp)

	result, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if result.UserID != "alice@example.com" || result.ExternalID != "alice@example.com" {
		t.Fatalf("nil linker must default UserID to the raw subject: %#v", result)
	}
}

func TestOIDCFederation_WiredLinkerResolvesUserID(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	linker := &fakeLinker{userID: "local-account-42"}
	auth, err := NewOIDCFederationAuthenticator(OIDCFederationConfig{
		Name:                  "test-idp",
		AuthorizationEndpoint: idp.srv.URL + "/authorize",
		TokenEndpoint:         idp.srv.URL + "/token",
		UserinfoEndpoint:      idp.srv.URL + "/userinfo",
		ClientID:              idp.expectedClient,
		ClientSecret:          idp.expectedSecret,
		RedirectURI:           "https://as.example/callback",
	}, WithUserLinker(linker))
	if err != nil {
		t.Fatalf("NewOIDCFederationAuthenticator: %v", err)
	}

	result, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if result.UserID != "local-account-42" {
		t.Fatalf("UserID = %q, want linker-resolved %q", result.UserID, "local-account-42")
	}
	// ExternalID is ALWAYS the raw external subject — never rewritten by the
	// linker, regardless of what UserID resolves to.
	if result.ExternalID != "alice@example.com" {
		t.Fatalf("ExternalID = %q, want raw subject %q (must never be rewritten)", result.ExternalID, "alice@example.com")
	}
	if linker.gotProvider != "test-idp" || linker.gotSubject != "alice@example.com" {
		t.Fatalf("linker called with (%q, %q), want (%q, %q)", linker.gotProvider, linker.gotSubject, "test-idp", "alice@example.com")
	}
}

func TestOIDCFederation_WiredLinkerErrorFailsCallback(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	sentinel := errors.New("account conflict")
	linker := &fakeLinker{err: sentinel}
	auth, err := NewOIDCFederationAuthenticator(OIDCFederationConfig{
		Name:                  "test-idp",
		AuthorizationEndpoint: idp.srv.URL + "/authorize",
		TokenEndpoint:         idp.srv.URL + "/token",
		UserinfoEndpoint:      idp.srv.URL + "/userinfo",
		ClientID:              idp.expectedClient,
		ClientSecret:          idp.expectedSecret,
		RedirectURI:           "https://as.example/callback",
	}, WithUserLinker(linker))
	if err != nil {
		t.Fatalf("NewOIDCFederationAuthenticator: %v", err)
	}

	result, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if result != nil {
		t.Fatalf("expected nil result on linker error, got %#v", result)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("Callback error = %v, want the linker's own error unwrapped (oracle-leak hardening: no shape change)", err)
	}
}

func TestOIDCFederation_ConstructorRejectsMissingFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  OIDCFederationConfig
	}{
		{"missing name", OIDCFederationConfig{AuthorizationEndpoint: "x", TokenEndpoint: "y", ClientID: "a", ClientSecret: "b", RedirectURI: "c"}},
		{"missing authz endpoint", OIDCFederationConfig{Name: "n", TokenEndpoint: "y", ClientID: "a", ClientSecret: "b", RedirectURI: "c"}},
		{"missing token endpoint", OIDCFederationConfig{Name: "n", AuthorizationEndpoint: "x", ClientID: "a", ClientSecret: "b", RedirectURI: "c"}},
		{"missing client id", OIDCFederationConfig{Name: "n", AuthorizationEndpoint: "x", TokenEndpoint: "y", ClientSecret: "b", RedirectURI: "c"}},
		{"missing client secret", OIDCFederationConfig{Name: "n", AuthorizationEndpoint: "x", TokenEndpoint: "y", ClientID: "a", RedirectURI: "c"}},
		{"missing redirect uri", OIDCFederationConfig{Name: "n", AuthorizationEndpoint: "x", TokenEndpoint: "y", ClientID: "a", ClientSecret: "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewOIDCFederationAuthenticator(c.cfg)
			if err == nil {
				t.Fatalf("expected error for case %q", c.name)
			}
		})
	}
}
