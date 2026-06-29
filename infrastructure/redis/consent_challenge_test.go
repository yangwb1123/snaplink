package redis

import (
	"testing"
	"time"
)

func TestConsentChallengeStore_IssueConsumeSingleUse(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewConsentChallengeStore(rdb)
	scopes := []string{"openid", "profile", "email"}

	id := s.Issue("user-1", "client-1", scopes)
	if id == "" {
		t.Fatal("Issue returned empty id")
	}

	// Exact match (scope order independent) consumes once.
	if !s.Consume(id, "user-1", "client-1", []string{"email", "openid", "profile"}) {
		t.Fatal("Consume should succeed on exact (order-independent) match")
	}
	// Single-use: second Consume of the same id fails.
	if s.Consume(id, "user-1", "client-1", scopes) {
		t.Fatal("Consume must be single-use (second call should fail)")
	}
}

func TestConsentChallengeStore_RejectsMismatch(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewConsentChallengeStore(rdb)
	scopes := []string{"openid", "profile"}

	cases := []struct {
		name          string
		user, client  string
		consumeScopes []string
	}{
		{"wrong user", "other", "client-1", scopes},
		{"wrong client", "user-1", "other", scopes},
		{"extra scope", "user-1", "client-1", []string{"openid", "profile", "email"}},
		{"missing scope", "user-1", "client-1", []string{"openid"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := s.Issue("user-1", "client-1", scopes)
			if s.Consume(id, tc.user, tc.client, tc.consumeScopes) {
				t.Fatalf("Consume must reject %s", tc.name)
			}
		})
	}
}

func TestConsentChallengeStore_UnknownAndExpired(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	s := NewConsentChallengeStore(rdb)

	if s.Consume("never-issued", "u", "c", nil) {
		t.Fatal("unknown id must not consume")
	}

	id := s.Issue("u", "c", []string{"openid"})
	mr.FastForward(consentChallengeTTL + time.Second)
	if s.Consume(id, "u", "c", []string{"openid"}) {
		t.Fatal("expired challenge (past TTL) must not consume")
	}
}
