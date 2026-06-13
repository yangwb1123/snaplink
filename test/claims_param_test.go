package ssotest

import "github.com/snaplink/sso/oauth"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	cpUserID   = "u-claims"
	cpClientID = "claims-client"
	cpSecret   = "claims-secret"
	cpPassword = "pw"
	cpRedirect = "https://app.example/cb"
)

// claimsCaptureAuthenticator records the AuthRequest.RequestedClaims
// payload so tests can verify it threaded through from /auth/login
// + PAR + JAR.
type claimsCaptureAuthenticator struct {
	mu     sync.Mutex
	claims json.RawMessage
}

func (c *claimsCaptureAuthenticator) Name() string             { return "password" }
func (c *claimsCaptureAuthenticator) LoginURL(_ string) string { return "" }
func (c *claimsCaptureAuthenticator) Authenticate(_ context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	if req == nil {
		return nil, errors.New("nil")
	}
	c.mu.Lock()
	c.claims = append(json.RawMessage(nil), req.RequestedClaims...)
	c.mu.Unlock()
	return &sso.AuthResult{UserID: cpUserID, Provider: "password"}, nil
}
func (c *claimsCaptureAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("no callback")
}
func (c *claimsCaptureAuthenticator) snapshot() json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.claims == nil {
		return nil
	}
	out := make(json.RawMessage, len(c.claims))
	copy(out, c.claims)
	return out
}

func newClaimsParamHarness(t *testing.T) (*httptest.Server, *claimsCaptureAuthenticator, oauth.PARStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: cpUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: cpClientID, Secret: cpSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{cpRedirect},
	})
	auth := &claimsCaptureAuthenticator{}
	parStore := defaultimpl.NewMemoryPARStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(auth),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPARStore(parStore, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, auth, parStore
}

func TestClaimsParam_AcceptedAndThreaded(t *testing.T) {
	srv, auth, _ := newClaimsParamHarness(t)
	// This verifies the claims parameter is parsed and threaded to the
	// authenticator with both branches intact. The id_token.acr request is
	// now ENFORCED (the AS must achieve the requested ACR — see TestClaimsACR_*),
	// so this threading test uses a non-enforced id_token claim to keep both
	// sections present without tripping the ACR gate.
	claims := `{"userinfo":{"email":null,"name":{"essential":true}},"id_token":{"email":null}}`
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(claims),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, rb)
	}
	got := auth.snapshot()
	if len(got) == 0 {
		t.Fatalf("authenticator saw no RequestedClaims")
	}
	// Round-trip through a generic decode to confirm shape preserved.
	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("requested claims not parseable: %v", err)
	}
	if _, ok := parsed["userinfo"].(map[string]any); !ok {
		t.Errorf("userinfo branch missing: %v", parsed)
	}
	if _, ok := parsed["id_token"].(map[string]any); !ok {
		t.Errorf("id_token branch missing: %v", parsed)
	}
}

func TestClaimsParam_RejectsNonObject(t *testing.T) {
	srv, _, _ := newClaimsParamHarness(t)
	// JSON array, not an object → MUST be rejected per §5.5.
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(`["not", "an", "object"]`),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out["error"] != sso.ErrInvalidRequest {
		t.Errorf("error=%v want %q", out["error"], sso.ErrInvalidRequest)
	}
}

func TestClaimsParam_RejectsInnerNonObject(t *testing.T) {
	// `userinfo` MUST itself be a JSON object per §5.5.
	srv, _, _ := newClaimsParamHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(`{"userinfo": "not-an-object"}`),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

func TestClaimsParam_RejectsTypoedEssentialBool(t *testing.T) {
	// The classic RP misconfig: `{"essential": "true"}` (string)
	// instead of `{"essential": true}` (bool). The old validator
	// silently accepted any inner JSON; the new one rejects so
	// the RP sees the bug immediately instead of debugging "why
	// is my essential claim being ignored".
	srv, _, _ := newClaimsParamHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(`{"userinfo": {"email": {"essential": "true"}}}`),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 on essential=\"true\" typo", resp.StatusCode)
	}
}

func TestClaimsParam_RejectsValuesNotAnArray(t *testing.T) {
	// `values` MUST be an array per §5.5.1. RP passing a scalar
	// is a typo for `value` (singular) — surface it.
	srv, _, _ := newClaimsParamHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(`{"id_token": {"acr": {"values": "level-2"}}}`),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 on values=string", resp.StatusCode)
	}
}

func TestClaimsParam_AcceptsNullPerSpec(t *testing.T) {
	// `{"email": null}` is the canonical "just request this claim,
	// no constraints" shape. MUST be accepted.
	srv, _, _ := newClaimsParamHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(`{"userinfo": {"email": null, "name": {"essential": true}}}`),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 on valid mixed shape", resp.StatusCode)
	}
}

func TestClaimsParam_PARPushSurvives(t *testing.T) {
	srv, auth, store := newClaimsParamHarness(t)
	uri, _ := store.Issue(context.Background(), &oauth.PARRequest{
		ClientID:    cpClientID,
		RedirectURI: cpRedirect,
		Claims:      json.RawMessage(`{"userinfo":{"email":null}}`),
		ExpiresAt:   time.Now().Add(time.Minute),
	})
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   cpClientID,
		"credential":  map[string]string{"username": cpUserID, "password": cpPassword},
		"request_uri": uri,
	})
	resp, _ := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	got := auth.snapshot()
	if len(got) == 0 {
		t.Fatalf("RequestedClaims not threaded from PAR")
	}
	var parsed map[string]any
	_ = json.Unmarshal(got, &parsed)
	if _, ok := parsed["userinfo"].(map[string]any); !ok {
		t.Errorf("PAR-pushed userinfo branch lost: %v", parsed)
	}
}

func TestClaimsParam_DiscoveryAdvertises(t *testing.T) {
	srv, _, _ := newClaimsParamHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if v, _ := doc["claims_parameter_supported"].(bool); !v {
		t.Errorf("claims_parameter_supported = %v want true", doc["claims_parameter_supported"])
	}
}
