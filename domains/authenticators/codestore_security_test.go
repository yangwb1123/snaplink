package authenticators

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestMemoryCodeStore_InvalidatesAfterMaxFailedAttempts(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStore()
	if err := store.Save(context.Background(), "k", "123456", time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for i := 0; i < DefaultCodeMaxAttempts; i++ {
		if err := store.Verify(context.Background(), "k", "000000"); !errors.Is(err, ErrCodeInvalid) {
			t.Fatalf("failed attempt %d: %v", i+1, err)
		}
	}
	if err := store.Verify(context.Background(), "k", "123456"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("correct code after exhaustion = %v, want ErrCodeInvalid", err)
	}
}

func TestMemoryCodeStore_EnforcesIdentityAndTenantSendQuotas(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStoreWithQuota(0, CodeSendQuota{IdentityLimit: 2, TenantLimit: 3, Window: time.Hour})
	ctxA := spi.WithCodeSendTenant(context.Background(), "tenant-a")
	for i := 0; i < 2; i++ {
		if err := store.Save(ctxA, "email:a@example.com", "code", time.Minute); err != nil {
			t.Fatalf("identity send %d: %v", i+1, err)
		}
	}
	if err := store.Save(ctxA, "email:a@example.com", "blocked", time.Minute); !errors.Is(err, spi.ErrCodeSendQuotaExceeded) {
		t.Fatalf("identity quota = %v", err)
	}
	if err := store.Save(ctxA, "email:b@example.com", "code", time.Minute); err != nil {
		t.Fatalf("tenant third send: %v", err)
	}
	if err := store.Save(ctxA, "email:c@example.com", "blocked", time.Minute); !errors.Is(err, spi.ErrCodeSendQuotaExceeded) {
		t.Fatalf("tenant quota = %v", err)
	}
	ctxB := spi.WithCodeSendTenant(context.Background(), "tenant-b")
	if err := store.Save(ctxB, "email:a@example.com", "isolated", time.Minute); err != nil {
		t.Fatalf("tenant partition not isolated: %v", err)
	}
}

func TestMemoryCodeStore_InvalidateRefundsSendQuota(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStoreWithQuota(0, CodeSendQuota{IdentityLimit: 1, TenantLimit: 1, Window: time.Hour})
	ctx := spi.WithCodeSendTenant(context.Background(), "tenant")
	if err := store.Save(ctx, "phone:+1", "undelivered", time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Invalidate(ctx, "phone:+1", "undelivered"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if err := store.Save(ctx, "phone:+1", "retry", time.Minute); err != nil {
		t.Fatalf("quota was not refunded: %v", err)
	}
}

func TestMemoryCodeStore_InvalidateIsConditional(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStore()
	ctx := context.Background()
	if err := store.Save(ctx, "k", "current", time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Invalidate(ctx, "k", "stale"); err != nil {
		t.Fatalf("Invalidate stale: %v", err)
	}
	if err := store.Verify(ctx, "k", "current"); err != nil {
		t.Fatalf("stale invalidation removed current code: %v", err)
	}
}

func TestPhoneAuthenticator_SendFailureReleasesCooldown(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStore()
	sender := &captureSMS{err: errors.New("sms down")}
	authenticator := NewPhoneAuthenticator(store, sender)
	if err := authenticator.SendCode(context.Background(), "+1"); err == nil {
		t.Fatal("first SendCode should fail")
	}
	sender.err = nil
	if err := authenticator.SendCode(context.Background(), "+1"); err != nil {
		t.Fatalf("retry after delivery failure: %v", err)
	}
}

type failingEmailSender struct{ err error }

func (s *failingEmailSender) Send(context.Context, string, string) error { return s.err }

func TestEmailAuthenticators_SendFailureReleaseCooldown(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		new  func(CodeStore, EmailSender) interface {
			SendCode(context.Context, string) error
		}
	}{
		{"email", func(store CodeStore, sender EmailSender) interface {
			SendCode(context.Context, string) error
		} {
			return NewEmailAuthenticator(store, sender)
		}},
		{"magic_link", func(store CodeStore, sender EmailSender) interface {
			SendCode(context.Context, string) error
		} {
			return NewMagicLinkAuthenticator(store, sender, "https://sso.example.com/login/")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryCodeStore()
			sender := &failingEmailSender{err: errors.New("email down")}
			authenticator := tc.new(store, sender)
			if err := authenticator.SendCode(context.Background(), "a@example.com"); err == nil {
				t.Fatal("first SendCode should fail")
			}
			sender.err = nil
			if err := authenticator.SendCode(context.Background(), "a@example.com"); err != nil {
				t.Fatalf("retry after delivery failure: %v", err)
			}
		})
	}
}
