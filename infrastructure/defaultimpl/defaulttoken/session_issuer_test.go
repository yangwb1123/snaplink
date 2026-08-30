package defaulttoken

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
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

func TestSessionTokenIssuer_MTLSCertLifetimeCeiling(t *testing.T) {
	t.Parallel()
	ttl := 2 * time.Hour
	cases := []struct {
		name     string
		notAfter time.Time
	}{
		{"before TTL", time.Now().Add(10 * time.Minute)},
		{"after TTL", time.Now().Add(3 * time.Hour)},
		{"zero uncapped", time.Time{}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := NewSessionTokenIssuer(WithSessionTokenTTL(ttl))
			tok, err := s.Issue(context.Background(), &core.Subject{ID: "u", NotAfter: tc.notAfter}, nil)
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			claims, err := s.Validate(context.Background(), tok.AccessToken)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			want := tok.CreatedAt.Add(ttl)
			if !tc.notAfter.IsZero() && tc.notAfter.Before(want) {
				want = tc.notAfter
			}
			if !claims.ExpiresAt.Equal(want) {
				t.Errorf("ExpiresAt = %v, want %v", claims.ExpiresAt, want)
			}
			wantIn := int(max(time.Duration(0), claims.ExpiresAt.Sub(tok.CreatedAt)).Seconds())
			if tok.ExpiresIn != wantIn {
				t.Errorf("ExpiresIn = %d, want %d", tok.ExpiresIn, wantIn)
			}
		})
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

func TestSessionTokenIssuer_SweepExpired(t *testing.T) {
	t.Parallel()
	s := NewSessionTokenIssuer(WithSessionTokenTTL(time.Millisecond))
	ctx := context.Background()
	expired := make([]string, 2)
	for i := range expired {
		tok, err := s.Issue(ctx, &core.Subject{ID: subjectN(i)}, nil)
		if err != nil {
			t.Fatalf("Issue expired token: %v", err)
		}
		expired[i] = tok.AccessToken
	}
	time.Sleep(20 * time.Millisecond)

	s.ttl = time.Hour
	live, err := s.Issue(ctx, &core.Subject{ID: "live"}, nil)
	if err != nil {
		t.Fatalf("Issue live token: %v", err)
	}
	s.lastSweep.Store(0)
	s.maybeSweepExpired(time.Now())

	for _, token := range expired {
		if _, ok := s.tokens.Load(token); ok {
			t.Errorf("expired token %q remains retained", token)
		}
	}
	if _, ok := s.tokens.Load(live.AccessToken); !ok {
		t.Error("live token was swept")
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
