package sqlite

import "github.com/snaplink/sso/protocols/oauth"

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newPARStoreForTest(t *testing.T) *PARStore {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "par.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	store, err := NewPARStore(dsn)
	if err != nil {
		t.Fatalf("NewPARStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func samplePARRequest() *oauth.PARRequest {
	return &oauth.PARRequest{
		ClientID:             "demo-client",
		ResponseType:         "code",
		RedirectURI:          "https://rp.example/cb",
		Scope:                []string{"openid", "profile", "email"},
		State:                "state-abc",
		Nonce:                "nonce-xyz",
		CodeChallenge:        "ch-S256-base64url-value",
		CodeChallengeMethod:  "S256",
		Resource:             []string{"https://api.example/v1", "https://api.example/v2"},
		AuthorizationDetails: json.RawMessage(`[{"type":"payment","amount":100}]`),
		LoginHint:            "alice@example",
		ResponseMode:         "form_post",
		ACRValues:            "urn:mace:incommon:iap:silver",
		UILocales:            "en-US fr-FR",
		Claims:               json.RawMessage(`{"id_token":{"email":{"essential":true}}}`),
		ExpiresAt:            time.Now().Add(90 * time.Second).UTC(),
	}
}

func TestPARStore_IssueAndConsumeRoundTrip(t *testing.T) {
	t.Parallel()
	store := newPARStoreForTest(t)
	ctx := context.Background()

	want := samplePARRequest()
	uri, err := store.Issue(ctx, want)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if uri == "" || uri[:len(oauth.PARURIPrefix)] != oauth.PARURIPrefix {
		t.Fatalf("Issue returned bad uri: %q", uri)
	}

	got, err := store.Consume(ctx, uri)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}

	// Spot-check every field threaded through oauth.PARRequest — a regression in
	// any column mapping is silent until /auth/login merges the pushed
	// value and finds it missing.
	if got.ClientID != want.ClientID || got.ResponseType != want.ResponseType ||
		got.RedirectURI != want.RedirectURI || got.State != want.State ||
		got.Nonce != want.Nonce || got.CodeChallenge != want.CodeChallenge ||
		got.CodeChallengeMethod != want.CodeChallengeMethod ||
		got.LoginHint != want.LoginHint || got.ResponseMode != want.ResponseMode ||
		got.ACRValues != want.ACRValues || got.UILocales != want.UILocales {
		t.Fatalf("scalar field mismatch:\n got %#v\nwant %#v", got, want)
	}
	if len(got.Scope) != len(want.Scope) {
		t.Fatalf("scope length: got %v want %v", got.Scope, want.Scope)
	}
	for i, s := range want.Scope {
		if got.Scope[i] != s {
			t.Fatalf("scope[%d]: got %q want %q", i, got.Scope[i], s)
		}
	}
	if len(got.Resource) != len(want.Resource) {
		t.Fatalf("resource length: got %v want %v", got.Resource, want.Resource)
	}
	for i, r := range want.Resource {
		if got.Resource[i] != r {
			t.Fatalf("resource[%d]: got %q want %q", i, got.Resource[i], r)
		}
	}
	if string(got.AuthorizationDetails) != string(want.AuthorizationDetails) {
		t.Fatalf("authorization_details: got %q want %q", got.AuthorizationDetails, want.AuthorizationDetails)
	}
	if string(got.Claims) != string(want.Claims) {
		t.Fatalf("claims: got %q want %q", got.Claims, want.Claims)
	}
	// ExpiresAt round-trips through int64 ns — equality on UnixNano().
	if got.ExpiresAt.UnixNano() != want.ExpiresAt.UnixNano() {
		t.Fatalf("ExpiresAt: got %v want %v", got.ExpiresAt, want.ExpiresAt)
	}
}

func TestPARStore_ConsumeIsSingleUse(t *testing.T) {
	t.Parallel()
	store := newPARStoreForTest(t)
	ctx := context.Background()

	uri, err := store.Issue(ctx, samplePARRequest())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := store.Consume(ctx, uri); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	_, err = store.Consume(ctx, uri)
	if !errors.Is(err, oauth.ErrPARNotFound) {
		t.Fatalf("second Consume: got %v, want oauth.ErrPARNotFound", err)
	}
}

func TestPARStore_ConsumeUnknownReturnsNotFound(t *testing.T) {
	t.Parallel()
	store := newPARStoreForTest(t)
	_, err := store.Consume(context.Background(), oauth.PARURIPrefix+"nonexistent")
	if !errors.Is(err, oauth.ErrPARNotFound) {
		t.Fatalf("unknown uri: got %v, want oauth.ErrPARNotFound", err)
	}
}

func TestPARStore_ExpiredEntryReturnsNotFound(t *testing.T) {
	t.Parallel()
	store := newPARStoreForTest(t)
	ctx := context.Background()

	req := samplePARRequest()
	req.ExpiresAt = time.Now().Add(-1 * time.Second).UTC() // already expired
	uri, err := store.Issue(ctx, req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = store.Consume(ctx, uri)
	if !errors.Is(err, oauth.ErrPARNotFound) {
		t.Fatalf("expired uri: got %v, want oauth.ErrPARNotFound", err)
	}
}

func TestPARStore_IssueNilRejected(t *testing.T) {
	t.Parallel()
	store := newPARStoreForTest(t)
	_, err := store.Issue(context.Background(), nil)
	if !errors.Is(err, oauth.ErrPARNotFound) {
		t.Fatalf("nil req: got %v, want oauth.ErrPARNotFound", err)
	}
}

func TestPARStore_OptionalFieldsNilSurviveRoundTrip(t *testing.T) {
	t.Parallel()
	store := newPARStoreForTest(t)
	ctx := context.Background()

	req := &oauth.PARRequest{
		ClientID:     "minimal-client",
		ResponseType: "code",
		ExpiresAt:    time.Now().Add(60 * time.Second).UTC(),
	}
	uri, err := store.Issue(ctx, req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := store.Consume(ctx, uri)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if len(got.AuthorizationDetails) > 0 {
		t.Fatalf("AuthorizationDetails should be empty/nil, got %q", got.AuthorizationDetails)
	}
	if len(got.Claims) > 0 {
		t.Fatalf("Claims should be empty/nil, got %q", got.Claims)
	}
	if len(got.Scope) != 0 || len(got.Resource) != 0 {
		t.Fatalf("Scope/Resource should be empty: scope=%v resource=%v", got.Scope, got.Resource)
	}
}

func TestPARStore_CallerMutationDoesNotLeak(t *testing.T) {
	t.Parallel()
	// Issue marshals slices into JSON columns, so post-Issue mutation
	// can't reach stored state. Verify by mutating then Consuming.
	store := newPARStoreForTest(t)
	ctx := context.Background()

	req := samplePARRequest()
	uri, err := store.Issue(ctx, req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req.Scope[0] = "MUTATED"
	req.Resource[0] = "MUTATED"

	got, err := store.Consume(ctx, uri)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.Scope[0] == "MUTATED" || got.Resource[0] == "MUTATED" {
		t.Fatalf("caller mutation leaked into stored state: scope=%v resource=%v",
			got.Scope, got.Resource)
	}
}
