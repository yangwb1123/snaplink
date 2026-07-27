package backendsemantics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
)

// TestSemantics_JTIReplay_MarkSeen: single-pass atomic semantics — the
// first sighting of a jti is (true, nil), any repeat within the window is
// (false, nil), and an unrelated jti is unaffected. Identical on every
// backend so a deployment can move the replay defense between memory and
// SQLite without changing replay outcomes.
func TestSemantics_JTIReplay_MarkSeen(t *testing.T) {
	for _, b := range jtiBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)
			exp := time.Now().Add(time.Minute)

			first, err := store.MarkSeen(context.Background(), "jti-a", exp)
			if err != nil || !first {
				t.Fatalf("first MarkSeen = (%v, %v), want (true, nil)", first, err)
			}
			replay, err := store.MarkSeen(context.Background(), "jti-a", exp)
			if err != nil || replay {
				t.Fatalf("replay MarkSeen = (%v, %v), want (false, nil)", replay, err)
			}
			other, err := store.MarkSeen(context.Background(), "jti-b", exp)
			if err != nil || !other {
				t.Fatalf("unrelated MarkSeen = (%v, %v), want (true, nil)", other, err)
			}
		})
	}
}

// TestSemantics_JTIReplay_EmptyJTI: every backend short-circuits "" as a
// first sighting — silently treating it as "seen" would let an attacker
// strip the claim to force rejections, and treating it as replayable would
// make the empty string a global one-shot key.
func TestSemantics_JTIReplay_EmptyJTI(t *testing.T) {
	for _, b := range jtiBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)
			for i := 0; i < 2; i++ {
				first, err := store.MarkSeen(context.Background(), "", time.Now().Add(time.Minute))
				if err != nil || !first {
					t.Fatalf("MarkSeen(\"\") #%d = (%v, %v), want (true, nil)", i+1, first, err)
				}
			}
		})
	}
}

func issuePAR(t *testing.T, store oauth.PARStore, expiresAt time.Time) string {
	t.Helper()
	uri, err := store.Issue(context.Background(), &oauth.PARRequest{
		ClientID:            "c-semantics",
		ResponseType:        "code",
		Scope:               []string{"openid", "profile"},
		CodeChallenge:       "challenge-semantics",
		CodeChallengeMethod: "S256",
		ExpiresAt:           expiresAt,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return uri
}

// TestSemantics_PAR_SingleUseConsume: Issue mints a spec-shaped
// request_uri; Consume returns the pushed payload exactly once; the second
// Consume fails with oauth.ErrPARNotFound (RFC 9126 section 2.2 single-use)
// on every backend.
func TestSemantics_PAR_SingleUseConsume(t *testing.T) {
	for _, b := range parBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)
			uri := issuePAR(t, store, time.Now().Add(oauth.DefaultPARTTL))
			if !strings.HasPrefix(uri, oauth.PARURIPrefix) {
				t.Fatalf("uri = %q, want prefix %q", uri, oauth.PARURIPrefix)
			}

			got, err := store.Consume(context.Background(), uri)
			if err != nil {
				t.Fatalf("first Consume: %v", err)
			}
			if got.ClientID != "c-semantics" || got.CodeChallenge != "challenge-semantics" {
				t.Fatalf("payload = %q/%q, want c-semantics/challenge-semantics", got.ClientID, got.CodeChallenge)
			}
			if len(got.Scope) != 2 {
				t.Fatalf("scope = %v, want 2 entries", got.Scope)
			}

			_, err = store.Consume(context.Background(), uri)
			assertSentinel(t, err, oauth.ErrPARNotFound)
		})
	}
}

// TestSemantics_PAR_UnknownAndExpired: unknown and expired request_uris
// collapse to oauth.ErrPARNotFound (oracle-resistance) on every backend.
func TestSemantics_PAR_UnknownAndExpired(t *testing.T) {
	for _, b := range parBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)

			_, err := store.Consume(context.Background(), oauth.PARURIPrefix+"never-issued")
			assertSentinel(t, err, oauth.ErrPARNotFound)

			uri := issuePAR(t, store, time.Now().Add(-time.Second))
			_, err = store.Consume(context.Background(), uri)
			assertSentinel(t, err, oauth.ErrPARNotFound)
		})
	}
}
