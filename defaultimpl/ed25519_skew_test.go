package defaultimpl_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// issueShortLived mints a token whose Exp is in the past (by skipping
// the TTL parameter and forcing a very short window). Used to exercise
// the skew leeway path.
func issueWithTinyTTL(t *testing.T, skew time.Duration) (*defaultimpl.Ed25519JWTIssuer, string) {
	t.Helper()
	j := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("test"),
		defaultimpl.WithEd25519TokenTTL(time.Millisecond), // expires ~immediately
		defaultimpl.WithEd25519MaxClockSkew(skew),
	)
	tok, err := j.Issue(context.Background(), &sso.Subject{ID: "user-1", ClientID: "client-1"}, []string{"read"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Sleep past the 1ms TTL so the token is expired in absolute time.
	time.Sleep(20 * time.Millisecond)
	return j, tok.AccessToken
}

func TestEd25519_ZeroSkewRejectsExpiredToken(t *testing.T) {
	j, raw := issueWithTinyTTL(t, 0)
	_, err := j.Validate(context.Background(), raw)
	if err == nil {
		t.Fatal("expected expired error with skew=0, got nil")
	}
}

func TestEd25519_PositiveSkewAcceptsRecentlyExpired(t *testing.T) {
	// 2s skew covers the ~20ms expiry overrun trivially.
	j, raw := issueWithTinyTTL(t, 2*time.Second)
	if _, err := j.Validate(context.Background(), raw); err != nil {
		t.Fatalf("token within skew window rejected: %v", err)
	}
}

func TestEd25519_SkewDoesNotAcceptStaleToken(t *testing.T) {
	// 100ms skew is too small for a token expired ~1.1s ago.
	j := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("test"),
		defaultimpl.WithEd25519TokenTTL(time.Millisecond),
		defaultimpl.WithEd25519MaxClockSkew(100*time.Millisecond),
	)
	tok, err := j.Issue(context.Background(), &sso.Subject{ID: "user-1", ClientID: "client-1"}, []string{"read"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := j.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("expected expired error past skew window, got nil")
	}
}
