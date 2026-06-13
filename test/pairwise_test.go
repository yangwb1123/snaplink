package ssotest

import "github.com/snaplink/sso/security"

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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func TestMemoryPairwiseSubjectStore_RoundTrip(t *testing.T) {
	s := security.NewMemoryPairwiseSubjectStore()
	if err := s.MapPairwise(context.Background(), "p123", "alice"); err != nil {
		t.Fatalf("MapPairwise: %v", err)
	}
	got, err := s.LocalSubject(context.Background(), "p123")
	if err != nil {
		t.Fatalf("LocalSubject: %v", err)
	}
	if got != "alice" {
		t.Errorf("LocalSubject = %q want alice", got)
	}
}

func TestMemoryPairwiseSubjectStore_UnknownReturnsSentinel(t *testing.T) {
	s := security.NewMemoryPairwiseSubjectStore()
	_, err := s.LocalSubject(context.Background(), "never-mapped")
	if !errors.Is(err, security.ErrPairwiseUnknown) {
		t.Errorf("err = %v want ErrPairwiseUnknown", err)
	}
}

func TestMemoryPairwiseSubjectStore_RemapIsIdempotent(t *testing.T) {
	s := security.NewMemoryPairwiseSubjectStore()
	for i := range 3 {
		if err := s.MapPairwise(context.Background(), "p1", "alice"); err != nil {
			t.Fatalf("MapPairwise #%d: %v", i, err)
		}
	}
	got, _ := s.LocalSubject(context.Background(), "p1")
	if got != "alice" {
		t.Errorf("got %q want alice", got)
	}
}

func TestMemoryPairwiseSubjectStore_RejectsEmptySub(t *testing.T) {
	s := security.NewMemoryPairwiseSubjectStore()
	if err := s.MapPairwise(context.Background(), "", "alice"); err == nil {
		t.Error("expected error for empty pairwise sub")
	}
	if err := s.MapPairwise(context.Background(), "p1", ""); err == nil {
		t.Error("expected error for empty local sub")
	}
}

func newPairwiseHarness(t *testing.T, subjectType, sectorURI string, redirects []string) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "user-alice", Email: "alice@example.com"})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                  "web-app",
		Active:              true,
		TokenStrategy:       "jwt",
		RedirectURIs:        redirects,
		SubjectType:         subjectType,
		SectorIdentifierURI: sectorURI,
	})

	jwt := defaultimpl.NewEd25519JWTIssuer()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", jwt),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(jwt),
		sso.WithPairwiseSubjectStore(security.NewMemoryPairwiseSubjectStore()),
		sso.WithPairwiseSalt("test-salt"),
		sso.WithAuthenticator(stubPasswordAuth{userID: "user-alice"}),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

type stubPasswordAuth struct{ userID string }

func (stubPasswordAuth) Name() string           { return "password" }
func (stubPasswordAuth) LoginURL(string) string { return "" }
func (s stubPasswordAuth) Authenticate(_ context.Context, _ *sso.AuthRequest) (*sso.AuthResult, error) {
	return &sso.AuthResult{UserID: s.userID, Provider: "password"}, nil
}
func (stubPasswordAuth) Callback(context.Context, *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("not used in pairwise tests")
}

func login(t *testing.T, base string, scope string) map[string]any {
	t.Helper()
	payload := map[string]any{
		"provider":   "password",
		"client_id":  "web-app",
		"credential": map[string]string{"username": "alice", "password": "any"},
	}
	if scope != "" {
		payload["scope"] = strings.Fields(scope)
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(base+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status = %d body=%s", resp.StatusCode, bb)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestPairwise_LoginEmitsOpaquePairwiseSub(t *testing.T) {
	srv := newPairwiseHarness(t, security.SubjectTypePairwise, "", []string{"https://web.example.com/cb"})
	body := login(t, srv.URL, "openid")
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatal("id_token missing")
	}
	sub := decodeIDTokenSub(t, idToken)
	if sub == "user-alice" {
		t.Errorf("sub %q is the local id — pairwise translation broken", sub)
	}
	if sub == "" {
		t.Error("sub empty")
	}
}

func TestPairwise_PublicClientGetsLocalSub(t *testing.T) {
	srv := newPairwiseHarness(t, security.SubjectTypePublic, "", []string{"https://web.example.com/cb"})
	body := login(t, srv.URL, "openid")
	idToken, _ := body["id_token"].(string)
	sub := decodeIDTokenSub(t, idToken)
	if sub != "user-alice" {
		t.Errorf("sub = %q want user-alice", sub)
	}
}

func TestPairwise_DifferentSectorsYieldDifferentSubs(t *testing.T) {
	srv1 := newPairwiseHarness(t, security.SubjectTypePairwise, "", []string{"https://web.example.com/cb"})
	srv2 := newPairwiseHarness(t, security.SubjectTypePairwise, "", []string{"https://other.example.com/cb"})
	b1 := login(t, srv1.URL, "openid")
	b2 := login(t, srv2.URL, "openid")
	sub1 := decodeIDTokenSub(t, b1["id_token"].(string))
	sub2 := decodeIDTokenSub(t, b2["id_token"].(string))
	if sub1 == sub2 {
		t.Errorf("sectors yielded the same sub %q — pairwise must vary by sector", sub1)
	}
}

func TestPairwise_SameSectorYieldsSameSub(t *testing.T) {
	srv := newPairwiseHarness(t, security.SubjectTypePairwise, "", []string{"https://web.example.com/cb"})
	b1 := login(t, srv.URL, "openid")
	b2 := login(t, srv.URL, "openid")
	sub1 := decodeIDTokenSub(t, b1["id_token"].(string))
	sub2 := decodeIDTokenSub(t, b2["id_token"].(string))
	if sub1 != sub2 {
		t.Errorf("same sector but subs differ: %q vs %q", sub1, sub2)
	}
}

func TestPairwise_SectorIdentifierURITakesPrecedence(t *testing.T) {
	// Two clients with different redirect_uri hosts but the same
	// sector_identifier_uri MUST share the pairwise sub.
	srv1 := newPairwiseHarness(t, security.SubjectTypePairwise,
		"https://sector.example.com/sector.json",
		[]string{"https://web-a.example.com/cb"})
	srv2 := newPairwiseHarness(t, security.SubjectTypePairwise,
		"https://sector.example.com/sector.json",
		[]string{"https://web-b.example.com/cb"})
	b1 := login(t, srv1.URL, "openid")
	b2 := login(t, srv2.URL, "openid")
	sub1 := decodeIDTokenSub(t, b1["id_token"].(string))
	sub2 := decodeIDTokenSub(t, b2["id_token"].(string))
	if sub1 != sub2 {
		t.Errorf("clients with same sector_identifier_uri got different subs: %q vs %q", sub1, sub2)
	}
}

func TestPairwise_DiscoveryAdvertisesPairwise(t *testing.T) {
	srv := newPairwiseHarness(t, security.SubjectTypePublic, "", []string{"https://web.example.com/cb"})
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	types, _ := doc["subject_types_supported"].([]any)
	if len(types) != 2 {
		t.Fatalf("subject_types_supported = %v want [public pairwise]", types)
	}
	saw := map[string]bool{}
	for _, t := range types {
		saw[t.(string)] = true
	}
	if !saw["public"] || !saw["pairwise"] {
		t.Errorf("subject_types_supported missing entries: %v", types)
	}
}

func TestPairwise_DiscoveryOmitsPairwiseWithoutStore(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	resp, err := http.Get(httpSrv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	types, _ := doc["subject_types_supported"].([]any)
	if len(types) != 1 || types[0] != "public" {
		t.Errorf("subject_types_supported = %v want [public] when no store wired", types)
	}
}

// decodeIDTokenSub extracts the sub claim from a JWS by base64-
// decoding the payload segment. Sufficient for tests — we don't
// need signature verification, just the claim contents.
func decodeIDTokenSub(t *testing.T, idToken string) string {
	t.Helper()
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token not JWS: %q", idToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	sub, _ := claims["sub"].(string)
	return sub
}
