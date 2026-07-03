package backendsemantics

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
)

func issueRefresh(t *testing.T, store oauth.RefreshTokenStore, token, familyID string, expiresAt time.Time) {
	t.Helper()
	err := store.Issue(context.Background(), token, &oauth.RefreshToken{
		UserID:    "u-semantics",
		ClientID:  "c-semantics",
		Scopes:    []string{"openid"},
		IssuedAt:  time.Now(),
		ExpiresAt: expiresAt,
		FamilyID:  familyID,
	})
	if err != nil {
		t.Fatalf("Issue(%s): %v", token, err)
	}
}

// TestSemantics_Refresh_ConsumeOnce: rotation single-use — the first
// Consume returns the record, the second (family tracking opted out) fails
// with oauth.ErrRefreshTokenNotFound on every backend.
func TestSemantics_Refresh_ConsumeOnce(t *testing.T) {
	for _, b := range refreshBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)
			issueRefresh(t, store, "rt-once", "", time.Now().Add(time.Hour))

			got, err := store.Consume(context.Background(), "rt-once")
			if err != nil {
				t.Fatalf("first Consume: %v", err)
			}
			if got.UserID != "u-semantics" || got.ClientID != "c-semantics" {
				t.Fatalf("payload = %q/%q, want u-semantics/c-semantics", got.UserID, got.ClientID)
			}

			_, err = store.Consume(context.Background(), "rt-once")
			assertSentinel(t, err, oauth.ErrRefreshTokenNotFound)
		})
	}
}

// TestSemantics_Refresh_FamilyReuseDetection: with a FamilyID stamped at
// Issue, a replay of the already-consumed leaf MUST surface as
// oauth.ErrRefreshTokenReused carrying the FamilyID, so the handler can
// kill the family (OAuth Security BCP section 4.13) — identically on every
// backend.
func TestSemantics_Refresh_FamilyReuseDetection(t *testing.T) {
	for _, b := range refreshBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)
			issueRefresh(t, store, "rt-fam-leaf", "fam-1", time.Now().Add(time.Hour))

			if _, err := store.Consume(context.Background(), "rt-fam-leaf"); err != nil {
				t.Fatalf("first Consume: %v", err)
			}

			info, err := store.Consume(context.Background(), "rt-fam-leaf")
			assertSentinel(t, err, oauth.ErrRefreshTokenReused)
			if info == nil || info.FamilyID != "fam-1" {
				t.Fatalf("reuse info = %+v, want FamilyID fam-1", info)
			}
		})
	}
}

// TestSemantics_Refresh_UnknownAndExpired: unknown and expired tokens are
// indistinguishable (oauth.ErrRefreshTokenNotFound) on every backend.
func TestSemantics_Refresh_UnknownAndExpired(t *testing.T) {
	for _, b := range refreshBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)

			_, err := store.Consume(context.Background(), "rt-never-issued")
			assertSentinel(t, err, oauth.ErrRefreshTokenNotFound)

			issueRefresh(t, store, "rt-stale", "", time.Now().Add(-time.Second))
			_, err = store.Consume(context.Background(), "rt-stale")
			assertSentinel(t, err, oauth.ErrRefreshTokenNotFound)
		})
	}
}

// TestSemantics_Refresh_DeleteFamilyClearsReuseLedger: DeleteFamily kills
// every active leaf AND forgets the reuse markers — a post-kill Consume is
// plain not-found (NOT a stale reuse signal) on every backend. Both
// bundled backends implement oauth.RefreshTokenFamilyTracker.
func TestSemantics_Refresh_DeleteFamilyClearsReuseLedger(t *testing.T) {
	for _, b := range refreshBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)
			tracker, ok := store.(oauth.RefreshTokenFamilyTracker)
			if !ok {
				t.Fatalf("%T does not implement RefreshTokenFamilyTracker", store)
			}
			issueRefresh(t, store, "rt-fam2-a", "fam-2", time.Now().Add(time.Hour))
			issueRefresh(t, store, "rt-fam2-b", "fam-2", time.Now().Add(time.Hour))

			killed, err := tracker.DeleteFamily(context.Background(), "fam-2")
			if err != nil {
				t.Fatalf("DeleteFamily: %v", err)
			}
			if killed != 2 {
				t.Fatalf("killed = %d, want 2", killed)
			}
			for _, tok := range []string{"rt-fam2-a", "rt-fam2-b"} {
				_, err := store.Consume(context.Background(), tok)
				assertSentinel(t, err, oauth.ErrRefreshTokenNotFound)
			}
		})
	}
}
