package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

func freshInvitationStore(t *testing.T) *InvitationStore {
	t.Helper()
	s, err := NewInvitationStore(testConfig(t))
	if err != nil {
		t.Fatalf("NewInvitationStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.ExecContext(context.Background(), "TRUNCATE invitations"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

func TestInvitation_IssueConsumeSingleUse(t *testing.T) {
	t.Parallel()
	s := freshInvitationStore(t)
	ctx := context.Background()

	inv := &core.Invitation{Token: "t1", TenantID: "acme", Email: "a@e.com", Role: core.TenantRoleAdmin, ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.Issue(ctx, inv); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := s.Consume(ctx, "t1")
	if err != nil || got.TenantID != "acme" || got.Role != core.TenantRoleAdmin || got.Email != "a@e.com" {
		t.Fatalf("Consume = %+v, %v; want acme/admin/a@e.com", got, err)
	}
	// Single-use: the destructive Consume removed the row.
	if _, err := s.Consume(ctx, "t1"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("second Consume err = %v, want ErrInvitationNotFound", err)
	}
}

func TestInvitation_MissingAndExpired(t *testing.T) {
	t.Parallel()
	s := freshInvitationStore(t)
	ctx := context.Background()

	// Missing → ErrInvitationNotFound (idempotent / oracle-safe).
	if _, err := s.Consume(ctx, "nope"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("missing err = %v, want ErrInvitationNotFound", err)
	}
	// Missing Consume again is still the same sentinel (idempotent delete).
	if _, err := s.Consume(ctx, "nope"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("repeat missing err = %v, want ErrInvitationNotFound", err)
	}

	// Expired: the row exists but Consume collapses to the same sentinel (the
	// row is still deleted — expired-consume is also single-use).
	if err := s.Issue(ctx, &core.Invitation{Token: "exp", TenantID: "acme", Email: "a@e.com", Role: core.TenantRoleMember, ExpiresAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatalf("Issue exp: %v", err)
	}
	if _, err := s.Consume(ctx, "exp"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("expired err = %v, want ErrInvitationNotFound", err)
	}
	// And it was deleted by that Consume — a second attempt is still not-found.
	if _, err := s.Consume(ctx, "exp"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("expired second Consume err = %v, want ErrInvitationNotFound", err)
	}
}

func TestInvitation_NanosecondRoundTrip(t *testing.T) {
	t.Parallel()
	s := freshInvitationStore(t)
	ctx := context.Background()

	// A non-round nanosecond expiry well in the future, to prove BIGINT keeps
	// the exact nanosecond value (no timestamptz truncation to microseconds).
	exp := time.Unix(0, time.Now().Add(time.Hour).UnixNano()+123456789)
	if err := s.Issue(ctx, &core.Invitation{Token: "ns", TenantID: "acme", Email: "a@e.com", Role: core.TenantRoleMember, ExpiresAt: exp}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := s.Consume(ctx, "ns")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ExpiresAt.UnixNano() != exp.UnixNano() {
		t.Fatalf("expires_at nanosecond round-trip lost: got %d want %d", got.ExpiresAt.UnixNano(), exp.UnixNano())
	}
}

func TestInvitation_IssueUpsertReplacesInFull(t *testing.T) {
	t.Parallel()
	s := freshInvitationStore(t)
	ctx := context.Background()

	exp1 := time.Now().Add(time.Minute)
	if err := s.Issue(ctx, &core.Invitation{Token: "dup", TenantID: "acme", Email: "first@e.com", Role: core.TenantRoleMember, ExpiresAt: exp1}); err != nil {
		t.Fatalf("Issue first: %v", err)
	}
	// Re-issue the SAME token with every non-PK column changed: ON CONFLICT
	// must replace the row in full (tenant, email, role, expiry).
	exp2 := time.Now().Add(2 * time.Hour)
	if err := s.Issue(ctx, &core.Invitation{Token: "dup", TenantID: "globex", Email: "second@e.com", Role: core.TenantRoleAdmin, ExpiresAt: exp2}); err != nil {
		t.Fatalf("Issue second: %v", err)
	}
	got, err := s.Consume(ctx, "dup")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.TenantID != "globex" || got.Email != "second@e.com" || got.Role != core.TenantRoleAdmin {
		t.Fatalf("upsert did not replace in full: %+v", got)
	}
	if got.ExpiresAt.UnixNano() != exp2.UnixNano() {
		t.Fatalf("upsert did not replace expires_at: got %d want %d", got.ExpiresAt.UnixNano(), exp2.UnixNano())
	}
	// Upsert must NOT have created a duplicate row.
	if _, err := s.Consume(ctx, "dup"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("upsert left a duplicate row: second Consume err = %v, want ErrInvitationNotFound", err)
	}
}

func TestInvitation_ListByTenantAndIsolation(t *testing.T) {
	t.Parallel()
	s := freshInvitationStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)

	if err := s.Issue(ctx, &core.Invitation{Token: "a1", TenantID: "acme", Email: "a1@e.com", Role: core.TenantRoleMember, ExpiresAt: exp}); err != nil {
		t.Fatalf("Issue a1: %v", err)
	}
	if err := s.Issue(ctx, &core.Invitation{Token: "a2", TenantID: "acme", Email: "a2@e.com", Role: core.TenantRoleAdmin, ExpiresAt: exp}); err != nil {
		t.Fatalf("Issue a2: %v", err)
	}
	if err := s.Issue(ctx, &core.Invitation{Token: "g1", TenantID: "globex", Email: "g@e.com", Role: core.TenantRoleGuest, ExpiresAt: exp}); err != nil {
		t.Fatalf("Issue g1: %v", err)
	}

	pending, err := s.ListByTenant(ctx, "acme")
	if err != nil || len(pending) != 2 {
		t.Fatalf("ListByTenant(acme) = %d, %v; want 2", len(pending), err)
	}
	for _, inv := range pending {
		if inv.TenantID != "acme" {
			t.Errorf("cross-tenant leak: %+v", inv)
		}
	}

	// Unknown tenant → empty roster, no error.
	if other, err := s.ListByTenant(ctx, "unknown"); err != nil || len(other) != 0 {
		t.Errorf("ListByTenant(unknown) = (%d, %v), want (0, nil)", len(other), err)
	}

	// Consuming one tenant's invite must not touch another tenant's roster.
	if _, err := s.Consume(ctx, "a1"); err != nil {
		t.Fatalf("Consume a1: %v", err)
	}
	if globex, _ := s.ListByTenant(ctx, "globex"); len(globex) != 1 {
		t.Errorf("globex roster wrongly affected: %d, want 1", len(globex))
	}
	if acme, _ := s.ListByTenant(ctx, "acme"); len(acme) != 1 {
		t.Errorf("acme roster after consuming a1 = %d, want 1", len(acme))
	}
}

func TestInvitation_RevokeByTenantEmail(t *testing.T) {
	t.Parallel()
	s := freshInvitationStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	// Two live tokens for the same recipient (re-send) + another recipient + another tenant.
	_ = s.Issue(ctx, &core.Invitation{Token: "r1", TenantID: "acme", Email: "gone@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "r2", TenantID: "acme", Email: "gone@e.com", Role: core.TenantRoleAdmin, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "k1", TenantID: "acme", Email: "keep@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "g1", TenantID: "globex", Email: "gone@e.com", Role: core.TenantRoleGuest, ExpiresAt: exp})

	if err := s.Revoke(ctx, "acme", "gone@e.com"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// EVERY token for the recipient is dead — a revoked invite can never be accepted.
	if _, err := s.Consume(ctx, "r1"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("r1 after revoke err = %v, want ErrInvitationNotFound", err)
	}
	if _, err := s.Consume(ctx, "r2"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("r2 after revoke err = %v, want ErrInvitationNotFound", err)
	}
	if acme, _ := s.ListByTenant(ctx, "acme"); len(acme) != 1 || acme[0].Email != "keep@e.com" {
		t.Errorf("acme roster after revoke = %+v, want only keep@e.com", acme)
	}
	if globex, _ := s.ListByTenant(ctx, "globex"); len(globex) != 1 {
		t.Errorf("globex roster wrongly affected: %d, want 1", len(globex))
	}
	// Idempotent: nothing pending is a no-op, not an error (no pending-invite oracle).
	if err := s.Revoke(ctx, "acme", "gone@e.com"); err != nil {
		t.Errorf("repeat Revoke err = %v, want nil", err)
	}
}
