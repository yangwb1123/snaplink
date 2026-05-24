package ssotest

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// ---------- harness ----------

const (
	rfClientID = "rf-client"
	rfSecret   = "rf-secret"
	rfUser     = "u-rf"
)

func newRefreshFamilyHarness(t *testing.T) (*httptest.Server, *defaultimpl.MemoryRefreshTokenStore, *audit.MemorySink) {
	t.Helper()
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rfUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rfClientID, Secret: rfSecret, Active: true,
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: rfUser, Provider: "password"}, nil
		},
	))
	store := defaultimpl.NewMemoryRefreshTokenStore()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))

	srv := sso.NewServer(
		sso.WithAuditRecorder(rec),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(store, time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, store, sink
}

func rfLogin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body := `{"provider":"password","client_id":"` + rfClientID +
		`","credential":{"username":"x","password":"y"}}`
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	dec := jsonDecodeRespBody(resp)
	out = dec
	r, _ := out["refresh_token"].(string)
	if r == "" {
		t.Fatalf("no refresh_token: %v", out)
	}
	return r
}

func rfRotate(t *testing.T, srv *httptest.Server, refresh string) (status int, body map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {rfClientID},
		"client_secret": {rfSecret},
		"refresh_token": {refresh},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	defer resp.Body.Close()
	body = jsonDecodeRespBody(resp)
	status = resp.StatusCode
	return
}

// ---------- family stamping ----------

func TestRefreshFamily_LoginStampsFamilyID(t *testing.T) {
	srv, store, _ := newRefreshFamilyHarness(t)
	refresh := rfLogin(t, srv)
	tok, err := store.Inspect(context.Background(), refresh)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if tok.FamilyID == "" {
		t.Error("expected non-empty FamilyID stamped on first issue")
	}
}

func TestRefreshFamily_RotationKeepsSameFamilyID(t *testing.T) {
	srv, store, _ := newRefreshFamilyHarness(t)
	refresh1 := rfLogin(t, srv)
	tok1, _ := store.Inspect(context.Background(), refresh1)
	originalFamily := tok1.FamilyID

	status, body := rfRotate(t, srv, refresh1)
	if status != http.StatusOK {
		t.Fatalf("rotation status=%d", status)
	}
	refresh2, _ := body["refresh_token"].(string)
	if refresh2 == "" || refresh2 == refresh1 {
		t.Fatalf("expected fresh rotated token, got %q", refresh2)
	}
	tok2, err := store.Inspect(context.Background(), refresh2)
	if err != nil {
		t.Fatalf("inspect rotated: %v", err)
	}
	if tok2.FamilyID != originalFamily {
		t.Errorf("rotation broke family: original=%q rotated=%q",
			originalFamily, tok2.FamilyID)
	}
}

// ---------- reuse detection ----------

func TestRefreshFamily_ReusedTokenKillsFamily(t *testing.T) {
	srv, store, sink := newRefreshFamilyHarness(t)
	refresh1 := rfLogin(t, srv)

	// First rotation succeeds, returns refresh2.
	status, body := rfRotate(t, srv, refresh1)
	if status != http.StatusOK {
		t.Fatalf("first rotation status=%d", status)
	}
	refresh2, _ := body["refresh_token"].(string)
	if refresh2 == "" {
		t.Fatal("missing refresh2")
	}

	// Replay refresh1 (the consumed leaf) — this is the reuse signal.
	// Per OAuth Security BCP §4.13 the entire family must die,
	// including the active refresh2 the attacker may have stolen.
	status2, body2 := rfRotate(t, srv, refresh1)
	if status2 != http.StatusBadRequest {
		t.Errorf("replay status=%d want 400", status2)
	}
	if body2["error"] != "invalid_grant" {
		t.Errorf("replay error=%v want invalid_grant", body2["error"])
	}

	// refresh2 MUST now be dead — Consume returns not-found, not
	// the rotation grant.
	if _, err := store.Consume(context.Background(), refresh2); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("refresh2 survived family revocation: err=%v", err)
	}

	// Audit event must have fired.
	events, _ := sink.Query(context.Background(), audit.Query{})
	var reuseEvent *audit.Event
	for _, e := range events {
		if e.Type == audit.EventRefreshTokenReuse {
			reuseEvent = e
			break
		}
	}
	if reuseEvent == nil {
		t.Fatal("expected refresh_token_reuse_detected event")
	}
	if reuseEvent.Outcome != audit.OutcomeFailure {
		t.Errorf("outcome=%q want failure", reuseEvent.Outcome)
	}
	if reuseEvent.Metadata["killed"] == "" {
		t.Error("expected killed count in metadata")
	}
}

func TestRefreshFamily_DirectFamilyTrackerSPI(t *testing.T) {
	store := defaultimpl.NewMemoryRefreshTokenStore()
	ctx := context.Background()

	// Issue three tokens in the same family + one in a different family.
	_ = store.Issue(ctx, "t1", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyID: "fam-1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	_ = store.Issue(ctx, "t2", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyID: "fam-1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	_ = store.Issue(ctx, "t3", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyID: "fam-1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	_ = store.Issue(ctx, "tx", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyID: "fam-2",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	n, err := store.DeleteFamily(ctx, "fam-1")
	if err != nil {
		t.Fatalf("DeleteFamily: %v", err)
	}
	if n != 3 {
		t.Errorf("killed=%d want 3", n)
	}
	// fam-2 survives.
	if _, err := store.Consume(ctx, "tx"); err != nil {
		t.Errorf("fam-2 token incorrectly deleted: %v", err)
	}
	// fam-1 tokens are gone.
	for _, tok := range []string{"t1", "t2", "t3"} {
		if _, err := store.Consume(ctx, tok); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
			t.Errorf("expected not-found for %q after family revoke, got %v", tok, err)
		}
	}
}

func TestRefreshFamily_EmptyFamilyIDIsNoOp(t *testing.T) {
	store := defaultimpl.NewMemoryRefreshTokenStore()
	n, err := store.DeleteFamily(context.Background(), "")
	if err != nil {
		t.Errorf("err=%v", err)
	}
	if n != 0 {
		t.Errorf("n=%d want 0", n)
	}
}

func TestRefreshFamily_ConsumeReusedReturnsSentinel(t *testing.T) {
	store := defaultimpl.NewMemoryRefreshTokenStore()
	ctx := context.Background()
	_ = store.Issue(ctx, "tok-reuse", &oauth.RefreshToken{
		UserID: "u", ClientID: "c", FamilyID: "fam-reuse",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	// First consume succeeds.
	if _, err := store.Consume(ctx, "tok-reuse"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	// Second consume is a reuse.
	tok, err := store.Consume(ctx, "tok-reuse")
	if !errors.Is(err, oauth.ErrRefreshTokenReused) {
		t.Errorf("err=%v want oauth.ErrRefreshTokenReused", err)
	}
	if tok == nil || tok.FamilyID != "fam-reuse" {
		t.Errorf("expected family stamped on reuse-detection oauth.RefreshToken, got %+v", tok)
	}
}

// ---------- helpers ----------

func jsonDecodeRespBody(resp *http.Response) map[string]any {
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}
