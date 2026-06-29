package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
)

func newDeviceCode(deviceCode, userCode string, ttl time.Duration) *oauth.DeviceCode {
	return &oauth.DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   "client-1",
		Scopes:     []string{"openid", "profile"},
		Interval:   5 * time.Second,
		ExpiresAt:  time.Now().Add(ttl),
	}
}

func TestDeviceCodeStore_IssueAndLookup(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewDeviceCodeStore(rdb)

	dc := newDeviceCode("dev-abc", "WXYZ-1234", time.Minute)
	if err := s.Issue(ctx, dc); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	byDev, err := s.GetByDeviceCode(ctx, "dev-abc")
	if err != nil {
		t.Fatalf("GetByDeviceCode: %v", err)
	}
	if byDev.UserCode != "WXYZ-1234" || byDev.ClientID != "client-1" {
		t.Fatalf("round-trip mismatch: %+v", byDev)
	}
	byUser, err := s.GetByUserCode(ctx, "WXYZ-1234")
	if err != nil {
		t.Fatalf("GetByUserCode: %v", err)
	}
	if byUser.DeviceCode != "dev-abc" {
		t.Fatalf("user_code pointer resolved to wrong device_code: %q", byUser.DeviceCode)
	}
}

func TestDeviceCodeStore_OracleLeak(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewDeviceCodeStore(rdb)

	// Unknown device_code and unknown user_code both collapse to the
	// same sentinel.
	if _, err := s.GetByDeviceCode(ctx, "ghost"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("unknown device_code must be ErrDeviceCodeNotFound, got %v", err)
	}
	if _, err := s.GetByUserCode(ctx, "GHOST"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("unknown user_code must be ErrDeviceCodeNotFound, got %v", err)
	}

	// Expired device code: same sentinel via either lookup path.
	if err := s.Issue(ctx, newDeviceCode("dev-exp", "EXP-0000", 30*time.Second)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mr.FastForward(31 * time.Second)
	if _, err := s.GetByDeviceCode(ctx, "dev-exp"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("expired device_code must collapse to ErrDeviceCodeNotFound, got %v", err)
	}
	if _, err := s.GetByUserCode(ctx, "EXP-0000"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("expired user_code must collapse to ErrDeviceCodeNotFound, got %v", err)
	}
}

func TestDeviceCodeStore_ApproveDeny(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewDeviceCodeStore(rdb)

	if err := s.Issue(ctx, newDeviceCode("dev-1", "APRV-1111", time.Minute)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	attrs := map[string]string{"email": "u@example.com"}
	if err := s.Approve(ctx, "APRV-1111", "user-7", "password", attrs); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	got, err := s.GetByDeviceCode(ctx, "dev-1")
	if err != nil {
		t.Fatalf("GetByDeviceCode: %v", err)
	}
	if !got.Approved || got.UserID != "user-7" || got.Provider != "password" {
		t.Fatalf("approval not persisted: %+v", got)
	}
	if got.Attributes["email"] != "u@example.com" {
		t.Fatalf("attributes not persisted: %+v", got.Attributes)
	}

	// Deny on a fresh code.
	if err := s.Issue(ctx, newDeviceCode("dev-2", "DENY-2222", time.Minute)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Deny(ctx, "DENY-2222"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	got2, err := s.GetByDeviceCode(ctx, "dev-2")
	if err != nil {
		t.Fatalf("GetByDeviceCode: %v", err)
	}
	if !got2.Denied {
		t.Fatalf("denial not persisted: %+v", got2)
	}

	// Approve / Deny on unknown user_code → not found.
	if err := s.Approve(ctx, "NOPE-0000", "x", "y", nil); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("Approve unknown must be ErrDeviceCodeNotFound, got %v", err)
	}
	if err := s.Deny(ctx, "NOPE-0000"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("Deny unknown must be ErrDeviceCodeNotFound, got %v", err)
	}
}

func TestDeviceCodeStore_UpdateLastPollPreservesTTL(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewDeviceCodeStore(rdb)

	if err := s.Issue(ctx, newDeviceCode("dev-poll", "POLL-9999", 30*time.Second)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	when := time.Now()
	if err := s.UpdateLastPoll(ctx, "dev-poll", when); err != nil {
		t.Fatalf("UpdateLastPoll: %v", err)
	}
	got, err := s.GetByDeviceCode(ctx, "dev-poll")
	if err != nil {
		t.Fatalf("GetByDeviceCode: %v", err)
	}
	if got.LastPoll.IsZero() {
		t.Fatal("last_poll not persisted")
	}

	// KEEPTTL means the mutation did not extend the code's lifetime: it
	// still expires at the original boundary.
	mr.FastForward(31 * time.Second)
	if _, err := s.GetByDeviceCode(ctx, "dev-poll"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("UpdateLastPoll must not extend TTL; want expired, got %v", err)
	}

	if err := s.UpdateLastPoll(ctx, "ghost", when); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("UpdateLastPoll unknown must be ErrDeviceCodeNotFound, got %v", err)
	}
}

func TestDeviceCodeStore_DeleteReapsBothKeys(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewDeviceCodeStore(rdb)

	if err := s.Issue(ctx, newDeviceCode("dev-del", "DEL-3333", time.Minute)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Delete(ctx, "dev-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Both the record and the user_code pointer are gone (single-use).
	if _, err := s.GetByDeviceCode(ctx, "dev-del"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("device_code must be gone after Delete, got %v", err)
	}
	if _, err := s.GetByUserCode(ctx, "DEL-3333"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("user_code pointer must be reaped after Delete, got %v", err)
	}
	// Delete is idempotent.
	if err := s.Delete(ctx, "dev-del"); err != nil {
		t.Fatalf("second Delete must be a no-op success, got %v", err)
	}
}

func TestDeviceCodeStore_Ping(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewDeviceCodeStore(rdb)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping live: %v", err)
	}
	var nilStore *DeviceCodeStore
	if err := nilStore.Ping(context.Background()); err == nil {
		t.Fatal("Ping on a nil store must error, not panic")
	}
}
