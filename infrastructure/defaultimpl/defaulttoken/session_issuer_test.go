package defaulttoken

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

func TestSessionTokenIssuer_RoundTrip(t *testing.T) {
	t.Parallel()
	s := NewSessionTokenIssuer(WithSessionTokenTTL(time.Hour))
	tok, err := s.Issue(context.Background(),
		&core.Subject{ID: "u-alice", Claims: map[string]string{"role": "admin"}},
		[]string{"read", "write"},
	)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok.AccessToken == "" {
		t.Error("AccessToken should be non-empty")
	}
	if tok.TokenType != core.TokenTypeBearer {
		t.Errorf("TokenType = %q, want Bearer", tok.TokenType)
	}
	if tok.ExpiresIn != int(time.Hour.Seconds()) {
		t.Errorf("ExpiresIn = %d", tok.ExpiresIn)
	}
	if tok.Scope != "read write" {
		t.Errorf("Scope = %q", tok.Scope)
	}

	claims, err := s.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "u-alice" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Extra["role"] != "admin" {
		t.Errorf("Extra = %v", claims.Extra)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "read" {
		t.Errorf("Scopes = %v", claims.Scopes)
	}
}

func TestSessionTokenIssuer_DefaultTTL(t *testing.T) {
	t.Parallel()
	s := NewSessionTokenIssuer()
	if s.ttl != defaultSessionTokenTTL {
		t.Errorf("ttl = %v, want default %v", s.ttl, defaultSessionTokenTTL)
	}
}

func TestSessionTokenIssuer_TokensAreUnique(t *testing.T) {
	t.Parallel()
	s := NewSessionTokenIssuer()
	seen := make(map[string]bool)
	for range 50 {
		tok, err := s.Issue(context.Background(), &core.Subject{ID: "u"}, nil)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[tok.AccessToken] {
			t.Fatalf("duplicate token issued: %q", tok.AccessToken)
		}
		seen[tok.AccessToken] = true
	}
}

func TestSessionTokenIssuer_IssueRequiresSubject(t *testing.T) {
	t.Parallel()
	s := NewSessionTokenIssuer()
	if _, err := s.Issue(context.Background(), nil, nil); err == nil {
		t.Error("expected error on nil subject")
	}
	if _, err := s.Issue(context.Background(), &core.Subject{}, nil); err == nil {
		t.Error("expected error on empty subject ID")
	}
}

func TestSessionTokenIssuer_ValidateUnknown(t *testing.T) {
	t.Parallel()
	s := NewSessionTokenIssuer()
	if _, err := s.Validate(context.Background(), "not-a-real-token"); err == nil {
		t.Error("expected error on unknown token")
	}
}

func TestSessionTokenIssuer_ExpiredTokenDeleted(t *testing.T) {
	t.Parallel()
	// TTL = 1ns guarantees the token is expired by the time Validate runs.
	s := NewSessionTokenIssuer(WithSessionTokenTTL(time.Nanosecond))
	tok, _ := s.Issue(context.Background(), &core.Subject{ID: "u"}, nil)
	time.Sleep(2 * time.Millisecond)
	if _, err := s.Validate(context.Background(), tok.AccessToken); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("err = %v, want expired", err)
	}
	// Expired-token Validate also deletes — second Validate must say "invalid".
	if _, err := s.Validate(context.Background(), tok.AccessToken); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("err after auto-delete = %v, want invalid", err)
	}
}

func TestSessionTokenIssuer_Revoke(t *testing.T) {
	t.Parallel()
	s := NewSessionTokenIssuer()
	tok, _ := s.Issue(context.Background(), &core.Subject{ID: "u"}, nil)
	if err := s.Revoke(context.Background(), tok.AccessToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := s.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Error("expected validate to fail after revoke")
	}
	if err := s.Revoke(context.Background(), tok.AccessToken); err == nil {
		t.Error("expected error on double-revoke")
	}
}
