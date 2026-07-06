package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreoauth"
	"github.com/snaplink/sso/protocols/oauth"
)

func TestMemoryRefreshTokenStore_MaxEntriesRejectsNewTokensAtCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	s.MaxEntries = 1
	info := &oauth.RefreshToken{UserID: "u1", ClientID: "c1", ExpiresAt: time.Now().Add(time.Hour)}

	if err := s.Issue(ctx, "tok-a", info); err != nil {
		t.Fatalf("Issue tok-a: %v", err)
	}
	err := s.Issue(ctx, "tok-b", info)
	if !errors.Is(err, memorystoreoauth.ErrStoreAtCapacity) {
		t.Fatalf("Issue tok-b at capacity = %v, want ErrStoreAtCapacity", err)
	}
	// Re-issuing an existing key (rotation into the same slot) isn't
	// growth and must not be rejected.
	if err := s.Issue(ctx, "tok-a", info); err != nil {
		t.Fatalf("re-Issue of existing key tok-a: %v", err)
	}
}

func TestMemoryRefreshTokenStore_StartReaperRemovesAbandonedExpiredTokens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	s.MaxEntries = 1
	s.StartReaper(5 * time.Millisecond)
	t.Cleanup(func() { _ = s.Close() })

	expired := &oauth.RefreshToken{UserID: "u1", ClientID: "c1", ExpiresAt: time.Now().Add(-time.Minute)}
	if err := s.Issue(ctx, "abandoned", expired); err != nil {
		t.Fatalf("Issue abandoned: %v", err)
	}

	fresh := &oauth.RefreshToken{UserID: "u2", ClientID: "c1", ExpiresAt: time.Now().Add(time.Hour)}
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := s.Issue(ctx, "fresh", fresh)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("reaper never freed capacity: last Issue err = %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestMemoryDeviceCodeStore_MaxEntriesRejectsNewCodesAtCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryDeviceCodeStore()
	s.MaxEntries = 1

	if err := s.Issue(ctx, &oauth.DeviceCode{DeviceCode: "d1", UserCode: "u1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("Issue d1: %v", err)
	}
	err := s.Issue(ctx, &oauth.DeviceCode{DeviceCode: "d2", UserCode: "u2", ExpiresAt: time.Now().Add(time.Hour)})
	if !errors.Is(err, memorystoreoauth.ErrStoreAtCapacity) {
		t.Fatalf("Issue d2 at capacity = %v, want ErrStoreAtCapacity", err)
	}
}

func TestMemoryDeviceCodeStore_StartReaperRemovesAbandonedExpiredCodes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryDeviceCodeStore()
	s.MaxEntries = 1
	s.StartReaper(5 * time.Millisecond)
	t.Cleanup(func() { _ = s.Close() })

	if err := s.Issue(ctx, &oauth.DeviceCode{DeviceCode: "abandoned", UserCode: "abandoned-uc", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("Issue abandoned: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		err := s.Issue(ctx, &oauth.DeviceCode{DeviceCode: "fresh", UserCode: "fresh-uc", ExpiresAt: time.Now().Add(time.Hour)})
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("reaper never freed capacity: last Issue err = %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestMemoryPARStore_MaxEntriesRejectsNewRequestsAtCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryPARStore()
	s.MaxEntries = 1

	if _, err := s.Issue(ctx, &oauth.PARRequest{ClientID: "c1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Issue #1: %v", err)
	}
	_, err := s.Issue(ctx, &oauth.PARRequest{ClientID: "c2", ExpiresAt: time.Now().Add(time.Minute)})
	if !errors.Is(err, memorystoreoauth.ErrStoreAtCapacity) {
		t.Fatalf("Issue #2 at capacity = %v, want ErrStoreAtCapacity", err)
	}
}

func TestMemoryPARStore_StartReaperRemovesAbandonedExpiredRequests(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryPARStore()
	s.MaxEntries = 1
	s.StartReaper(5 * time.Millisecond)
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.Issue(ctx, &oauth.PARRequest{ClientID: "abandoned", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("Issue abandoned: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := s.Issue(ctx, &oauth.PARRequest{ClientID: "fresh", ExpiresAt: time.Now().Add(time.Minute)})
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("reaper never freed capacity: last Issue err = %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestMemoryStores_CloseWithoutReaperIsNoOp(t *testing.T) {
	t.Parallel()
	if err := defaultimpl.NewMemoryRefreshTokenStore().Close(); err != nil {
		t.Errorf("refresh token Close: %v", err)
	}
	if err := defaultimpl.NewMemoryDeviceCodeStore().Close(); err != nil {
		t.Errorf("device code Close: %v", err)
	}
	if err := defaultimpl.NewMemoryPARStore().Close(); err != nil {
		t.Errorf("PAR Close: %v", err)
	}
}
