package sso_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func newTokenCacheServer(t *testing.T, opts ...sso.Option) *rcovServer {
	t.Helper()
	cache := defaultimpl.NewMemoryIdempotentCache(time.Hour)
	t.Cleanup(cache.Close)
	return rcovNewServer(t, append(opts, sso.WithIdempotentStore(cache))...)
}

func cachedTokenPost(t *testing.T, s *rcovServer, request map[string]any) (int, map[string]any) {
	t.Helper()
	return capPostJSONWithHeader(t, s.http.URL+"/token", "Idempotency-Key", "security-retry", request)
}

func refreshCacheRequest(refresh string) map[string]any {
	return map[string]any{"grant_type": "refresh_token", "refresh_token": refresh, "client_id": rcovClient, "client_secret": rcovSecret}
}

func TestTokenCacheDoesNotReplayConsumedAuthCode(t *testing.T) {
	s := newTokenCacheServer(t)
	code := rcovIssueEmptyAuthCode(t, s)
	request := map[string]any{"grant_type": "authorization_code", "code": code, "redirect_uri": rcovRedirect, "client_id": rcovClient, "client_secret": rcovSecret}
	if status, body := cachedTokenPost(t, s, request); status != http.StatusOK {
		t.Fatalf("first exchange = %d %v", status, body)
	}
	status, body := cachedTokenPost(t, s, request)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("consumed code replay = %d %v", status, body)
	}
}

func TestTokenCacheDoesNotMaskRefreshFamilyReuse(t *testing.T) {
	s := newTokenCacheServer(t)
	_, refresh := rcovDirectLogin(t, s)
	request := refreshCacheRequest(refresh)
	status, first := cachedTokenPost(t, s, request)
	if status != http.StatusOK || first["refresh_token"] == nil {
		t.Fatalf("first rotation = %d %v", status, first)
	}
	status, denied := cachedTokenPost(t, s, request)
	if status != http.StatusBadRequest || denied["error"] != "invalid_grant" {
		t.Fatalf("reuse = %d %v", status, denied)
	}
	request["refresh_token"] = first["refresh_token"]
	status, denied = cachedTokenPost(t, s, request)
	if status != http.StatusBadRequest || denied["error"] != "invalid_grant" {
		t.Fatalf("family descendant survived reuse = %d %v", status, denied)
	}
}

func TestRefreshGraceReplayRechecksSessionAndClient(t *testing.T) {
	for _, cause := range []string{"destroyed-session", "wrong-client", "revoked-successor", "revoked-access"} {
		t.Run(cause, func(t *testing.T) {
			s := newTokenCacheServer(t, sso.WithRefreshRotationGrace(time.Minute))
			_, refresh := rcovDirectLogin(t, s)
			original, err := s.refresh.Inspect(t.Context(), refresh)
			if err != nil || original.SID == "" {
				t.Fatalf("original refresh = %v %v", original, err)
			}
			request := refreshCacheRequest(refresh)
			status, first := cachedTokenPost(t, s, request)
			if status != http.StatusOK {
				t.Fatalf("first rotation = %d %v", status, first)
			}
			switch cause {
			case "destroyed-session":
				if err := s.sessions.Destroy(t.Context(), original.SID); err != nil {
					t.Fatal(err)
				}
			case "wrong-client":
				s.clients.AddSeed(&sso.Client{ID: "other", Secret: "other-secret", Active: true, TokenStrategy: "jwt"})
				request["client_id"], request["client_secret"] = "other", "other-secret"
			case "revoked-successor":
				if err := s.refresh.Delete(t.Context(), first["refresh_token"].(string)); err != nil {
					t.Fatal(err)
				}
			case "revoked-access":
				status, body := rcovPostJSONBasic(t, s.http.URL+"/token/revoke", rcovClient, rcovSecret, map[string]any{"token": first["access_token"]})
				if status != http.StatusOK {
					t.Fatalf("revoke = %d %v", status, body)
				}
			}
			status, denied := cachedTokenPost(t, s, request)
			if status != http.StatusBadRequest || denied["error"] != "invalid_grant" {
				t.Fatalf("unsafe grace replay = %d %v", status, denied)
			}
		})
	}
}

func TestRefreshGraceIsTheOnlyRefreshReplayWindow(t *testing.T) {
	s := newTokenCacheServer(t, sso.WithRefreshRotationGrace(time.Second))
	_, refresh := rcovDirectLogin(t, s)
	request := refreshCacheRequest(refresh)
	status, first := cachedTokenPost(t, s, request)
	if status != http.StatusOK {
		t.Fatalf("first rotation = %d %v", status, first)
	}
	status, replay := cachedTokenPost(t, s, request)
	if status != http.StatusOK || replay["refresh_token"] != first["refresh_token"] || replay["access_token"] != first["access_token"] {
		t.Fatalf("within grace = %d %v", status, replay)
	}
	if replay["_grant_deadline"] != nil {
		t.Fatal("internal replay deadline leaked onto the wire")
	}
	time.Sleep(1100 * time.Millisecond)
	status, replay = cachedTokenPost(t, s, request)
	if status != http.StatusBadRequest || replay["error"] != "invalid_grant" {
		t.Fatalf("past grace = %d %v", status, replay)
	}
}

func TestClientCredentialsReplayRechecksRevocationAndScopes(t *testing.T) {
	s := newTokenCacheServer(t)
	request := map[string]any{"grant_type": "client_credentials", "client_id": rcovClient, "client_secret": rcovSecret, "scope": "read"}
	status, first := cachedTokenPost(t, s, request)
	if status != http.StatusOK {
		t.Fatalf("first token = %d %v", status, first)
	}
	status, body := rcovPostJSONBasic(t, s.http.URL+"/token/revoke", rcovClient, rcovSecret, map[string]any{"token": first["access_token"]})
	if status != http.StatusOK {
		t.Fatalf("revoke = %d %v", status, body)
	}
	status, second := cachedTokenPost(t, s, request)
	if status != http.StatusOK || second["access_token"] == first["access_token"] {
		t.Fatalf("revoked token replayed = %d %v", status, second)
	}
	client, err := s.clients.Get(context.Background(), rcovClient)
	if err != nil {
		t.Fatal(err)
	}
	client.AllowedScopes = []string{"write"}
	s.clients.AddSeed(client)
	status, body = cachedTokenPost(t, s, request)
	if status != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Fatalf("stale client scope replay = %d %v", status, body)
	}
}

func TestClientCredentialsConcurrentLocalRetryReturnsOneToken(t *testing.T) {
	s := newTokenCacheServer(t)
	request := map[string]any{"grant_type": "client_credentials", "client_id": rcovClient, "client_secret": rcovSecret, "scope": "read"}
	var wg sync.WaitGroup
	results := make(chan string, 20)
	for range 20 {
		wg.Go(func() {
			status, body := cachedTokenPost(t, s, request)
			if status != http.StatusOK {
				t.Errorf("retry = %d %v", status, body)
				return
			}
			results <- body["access_token"].(string)
		})
	}
	wg.Wait()
	close(results)
	var first string
	for token := range results {
		if first == "" {
			first = token
		} else if token != first {
			t.Fatal("concurrent local retries minted distinct tokens")
		}
	}
}
