package backendsemantics

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
)

func issueAuthCode(t *testing.T, store oauth.AuthCodeStore, code string, expiresAt time.Time) {
	t.Helper()
	err := store.Issue(context.Background(), code, &oauth.AuthCode{
		UserID:    "u-semantics",
		ClientID:  "c-semantics",
		Scopes:    []string{"openid", "profile"},
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
}

// TestSemantics_AuthCode_SingleUseConsume: Consume returns the payload
// exactly once; the second Consume of the SAME code fails with the shared
// oauth.ErrAuthCodeNotFound sentinel on every backend (single-use claim
// behind the /token authorization_code oracle-leak collapse).
func TestSemantics_AuthCode_SingleUseConsume(t *testing.T) {
	for _, b := range authCodeBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)
			issueAuthCode(t, store, "ac-once", time.Now().Add(time.Minute))

			got, err := store.Consume(context.Background(), "ac-once")
			if err != nil {
				t.Fatalf("first Consume: %v", err)
			}
			if got.UserID != "u-semantics" || got.ClientID != "c-semantics" {
				t.Fatalf("payload = %q/%q, want u-semantics/c-semantics", got.UserID, got.ClientID)
			}
			if len(got.Scopes) != 2 {
				t.Fatalf("scopes = %v, want 2 entries", got.Scopes)
			}

			second, err := store.Consume(context.Background(), "ac-once")
			if second != nil {
				t.Fatalf("second Consume returned payload %+v, want nil", second)
			}
			assertSentinel(t, err, oauth.ErrAuthCodeNotFound)
		})
	}
}

// TestSemantics_AuthCode_UnknownAndExpired: unknown and expired codes are
// indistinguishable — both collapse to oauth.ErrAuthCodeNotFound on every
// backend, never a driver-specific error.
func TestSemantics_AuthCode_UnknownAndExpired(t *testing.T) {
	for _, b := range authCodeBackends {
		t.Run(b.name, func(t *testing.T) {
			store := b.make(t)

			_, err := store.Consume(context.Background(), "ac-never-issued")
			assertSentinel(t, err, oauth.ErrAuthCodeNotFound)

			issueAuthCode(t, store, "ac-stale", time.Now().Add(-time.Second))
			_, err = store.Consume(context.Background(), "ac-stale")
			assertSentinel(t, err, oauth.ErrAuthCodeNotFound)
		})
	}
}
