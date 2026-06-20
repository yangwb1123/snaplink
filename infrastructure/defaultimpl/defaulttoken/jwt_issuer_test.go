package defaulttoken

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

func TestJWTIssuer_RoundTrip(t *testing.T) {
	j := NewJWTIssuer(
		WithJWTSecret([]byte("test-secret-bytes-for-jwt-issuer")),
		WithJWTIssuer("test-issuer"),
		WithJWTTokenTTL(time.Hour),
	)
	tok, err := j.Issue(context.Background(),
		&core.Subject{ID: "u-alice", Claims: map[string]string{"team": "eng"}},
		[]string{"read"},
	)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok.AccessToken == "" {
		t.Error("AccessToken empty")
	}
	if tok.TokenType != core.TokenTypeBearer {
		t.Errorf("TokenType = %q", tok.TokenType)
	}
	if tok.ExpiresIn != int(time.Hour.Seconds()) {
		t.Errorf("ExpiresIn = %d", tok.ExpiresIn)
	}

	claims, err := j.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "u-alice" || claims.Issuer != "test-issuer" {
		t.Errorf("claims = %+v", claims)
	}
	if claims.Extra["team"] != "eng" {
		t.Errorf("Extra = %v", claims.Extra)
	}
}

func TestJWTIssuer_DefaultsApplied(t *testing.T) {
	j := NewJWTIssuer()
	if j.issuer != core.DefaultIssuer {
		t.Errorf("issuer = %q, want %q", j.issuer, core.DefaultIssuer)
	}
	if j.tokenTTL != defaultTokenTTL {
		t.Errorf("tokenTTL = %v, want default %v", j.tokenTTL, defaultTokenTTL)
	}
	if len(j.secret) != jwtSecretBytes {
		t.Errorf("secret len = %d, want generated %d", len(j.secret), jwtSecretBytes)
	}
}

func TestJWTIssuer_GeneratesUniqueTokens(t *testing.T) {
	j := NewJWTIssuer()
	seen := map[string]bool{}
	for i := range 20 {
		// Vary the subject so the same-content/same-secret signature differs;
		// the simple issuer stores by token string so identical subjects map
		// to the same token (memoized).
		tok, _ := j.Issue(context.Background(), &core.Subject{ID: subjectN(i)}, nil)
		if seen[tok.AccessToken] {
			t.Fatalf("duplicate token for distinct subject %d: %q", i, tok.AccessToken)
		}
		seen[tok.AccessToken] = true
	}
}

func subjectN(i int) string {
	// crude unique-subject helper for the dedupe test
	return "u-" + string(rune('a'+i))
}

func TestJWTIssuer_ValidateUnknown(t *testing.T) {
	j := NewJWTIssuer()
	if _, err := j.Validate(context.Background(), "no-such-token"); err == nil {
		t.Error("expected error on unknown token")
	}
}

func TestJWTIssuer_ValidateExpired(t *testing.T) {
	j := NewJWTIssuer(WithJWTTokenTTL(time.Nanosecond))
	tok, _ := j.Issue(context.Background(), &core.Subject{ID: "u"}, nil)
	time.Sleep(2 * time.Millisecond)
	if _, err := j.Validate(context.Background(), tok.AccessToken); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("err = %v, want expired", err)
	}
}

func TestJWTIssuer_Revoke(t *testing.T) {
	j := NewJWTIssuer()
	tok, _ := j.Issue(context.Background(), &core.Subject{ID: "u"}, nil)
	if err := j.Revoke(context.Background(), tok.AccessToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := j.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Error("expected validate to fail after revoke")
	}
	if err := j.Revoke(context.Background(), tok.AccessToken); err == nil {
		t.Error("expected error on double-revoke")
	}
}

func TestJWTIssuer_TokenContainsDot(t *testing.T) {
	// Loose contract check: buildToken emits "<payload-b64>.<sig-b64>" so
	// downstream tooling that parses by "." can rely on the structure.
	j := NewJWTIssuer()
	tok, _ := j.Issue(context.Background(), &core.Subject{ID: "u"}, nil)
	if !strings.Contains(tok.AccessToken, ".") {
		t.Errorf("AccessToken missing '.': %q", tok.AccessToken)
	}
}
