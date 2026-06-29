package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

func freshDeviceSecretStore(t *testing.T) *DeviceSecretStore {
	t.Helper()
	s, err := NewDeviceSecretStore(testConfig(t))
	if err != nil {
		t.Fatalf("NewDeviceSecretStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.ExecContext(context.Background(), "TRUNCATE device_secrets"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

func TestDeviceSecret_IssueConsume(t *testing.T) {
	t.Parallel()
	s := freshDeviceSecretStore(t)
	ctx := context.Background()

	// Nanosecond-precise expiry to assert exact BIGINT round-trip.
	exp := time.Unix(0, time.Now().Add(time.Minute).UnixNano()+123456789).UTC()
	ds := &core.DeviceSecret{Secret: "x1", Subject: "u1", SID: "s1", ClientID: "a", ExpiresAt: exp}
	if err := s.Issue(ctx, ds); err != nil {
		t.Fatalf("issue: %v", err)
	}

	got, err := s.Consume(ctx, "x1")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.Subject != "u1" || got.SID != "s1" || got.ClientID != "a" || got.Secret != "x1" {
		t.Errorf("binding=%+v", got)
	}
	if got.ExpiresAt.UnixNano() != exp.UnixNano() {
		t.Errorf("expires_at nanosecond round-trip lost: got %d want %d", got.ExpiresAt.UnixNano(), exp.UnixNano())
	}

	// Single-use: the second consume finds nothing (oracle-safe).
	if _, err := s.Consume(ctx, "x1"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
		t.Errorf("second consume err=%v want ErrDeviceSecretNotFound", err)
	}
}

func TestDeviceSecret_Missing(t *testing.T) {
	t.Parallel()
	s := freshDeviceSecretStore(t)
	if _, err := s.Consume(context.Background(), "nope"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
		t.Errorf("err=%v want ErrDeviceSecretNotFound", err)
	}
}

func TestDeviceSecret_Expired(t *testing.T) {
	t.Parallel()
	s := freshDeviceSecretStore(t)
	ctx := context.Background()
	if err := s.Issue(ctx, &core.DeviceSecret{Secret: "old", Subject: "u", ClientID: "c", ExpiresAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Expired is indistinguishable from missing — and the row is consumed.
	if _, err := s.Consume(ctx, "old"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
		t.Errorf("expired err=%v want ErrDeviceSecretNotFound", err)
	}
	// Consume deleted the expired row even though it returned not-found.
	if _, err := s.Consume(ctx, "old"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
		t.Errorf("re-consume err=%v want ErrDeviceSecretNotFound", err)
	}
}

func TestDeviceSecret_IssueReplacesInFull(t *testing.T) {
	t.Parallel()
	s := freshDeviceSecretStore(t)
	ctx := context.Background()

	first := &core.DeviceSecret{Secret: "dup", Subject: "u1", SID: "s1", ClientID: "c1", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.Issue(ctx, first); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	// Re-issue with the SAME secret but every other field changed: upsert must
	// replace the row in full (subject, sid, client_id, expires_at).
	newExp := time.Unix(0, time.Now().Add(2*time.Minute).UnixNano()).UTC()
	second := &core.DeviceSecret{Secret: "dup", Subject: "u2", SID: "s2", ClientID: "c2", ExpiresAt: newExp}
	if err := s.Issue(ctx, second); err != nil {
		t.Fatalf("second issue (upsert): %v", err)
	}

	got, err := s.Consume(ctx, "dup")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.Subject != "u2" || got.SID != "s2" || got.ClientID != "c2" {
		t.Errorf("upsert did not replace in full: %+v", got)
	}
	if got.ExpiresAt.UnixNano() != newExp.UnixNano() {
		t.Errorf("upsert expires_at = %d, want %d", got.ExpiresAt.UnixNano(), newExp.UnixNano())
	}
}

func TestDeviceSecret_RevokeBySubject(t *testing.T) {
	t.Parallel()
	s := freshDeviceSecretStore(t)
	ctx := context.Background()

	// Two bindings for u1, one for u2.
	for _, sec := range []string{"a", "b"} {
		if err := s.Issue(ctx, &core.DeviceSecret{Secret: sec, Subject: "u1", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("issue %s: %v", sec, err)
		}
	}
	if err := s.Issue(ctx, &core.DeviceSecret{Secret: "other", Subject: "u2", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("issue other: %v", err)
	}

	n, err := s.RevokeBySubject(ctx, "u1")
	if err != nil {
		t.Fatalf("RevokeBySubject: %v", err)
	}
	if n != 2 {
		t.Errorf("RevokeBySubject count = %d, want 2", n)
	}

	// u1's secrets are gone; u2's is untouched (no cross-subject leak).
	if _, err := s.Consume(ctx, "a"); !errors.Is(err, core.ErrDeviceSecretNotFound) {
		t.Errorf("revoked secret a still present: %v", err)
	}
	if got, err := s.Consume(ctx, "other"); err != nil || got.Subject != "u2" {
		t.Errorf("u2 binding wrongly affected: got=%+v err=%v", got, err)
	}

	// Idempotent: revoking again removes nothing.
	if n, err := s.RevokeBySubject(ctx, "u1"); err != nil || n != 0 {
		t.Errorf("idempotent RevokeBySubject = (%d, %v), want (0, nil)", n, err)
	}
}
