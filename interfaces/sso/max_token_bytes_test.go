package sso

import (
	"context"
	"strings"
	"testing"
)

// TestMaxTokenBytesGate proves WithMaxTokenBytes rejects an oversized bearer
// token BEFORE any issuer's Validate runs — the whole point of the gate is
// that a deliberately huge "token" string never gets to spend CPU on
// base64/JSON parsing ahead of the inevitable verification failure.
// Mirrors TestSupportedSigningAlgsGate's shape (signing_algs_test.go), the
// sibling Server-level pre-check.
func TestMaxTokenBytesGate(t *testing.T) {
	t.Parallel()
	fake := &fakeJWTIssuer{}
	s := NewServer(
		WithTokenIssuer("jwt", fake),
		WithMaxTokenBytes(16),
	)

	// Over the configured cap: rejected before the issuer runs.
	if _, _, err := s.validateAnyToken(context.Background(), strings.Repeat("a", 17)); err == nil {
		t.Error("oversized token accepted despite MaxTokenBytes=16")
	}
	if fake.validated {
		t.Error("issuer.Validate ran for an over-limit token (gate did not pre-filter)")
	}

	// Exactly at the cap: reaches the issuer.
	fake.validated = false
	if _, _, err := s.validateAnyToken(context.Background(), strings.Repeat("a", 16)); err != nil {
		t.Errorf("at-limit token rejected: %v", err)
	}
	if !fake.validated {
		t.Error("issuer.Validate did not run for an at-limit token")
	}
}

// TestMaxTokenBytesGate_UnsetUnbounded proves the default (option never
// wired) leaves bearer-token length completely unbounded — byte-identical
// to a build without this feature.
func TestMaxTokenBytesGate_UnsetUnbounded(t *testing.T) {
	t.Parallel()
	fake := &fakeJWTIssuer{}
	s := NewServer(WithTokenIssuer("jwt", fake))
	huge := strings.Repeat("a", 1<<20) // 1 MiB
	if _, _, err := s.validateAnyToken(context.Background(), huge); err != nil {
		t.Errorf("huge token rejected despite MaxTokenBytes unset: %v", err)
	}
	if !fake.validated {
		t.Error("issuer.Validate did not run")
	}
}
