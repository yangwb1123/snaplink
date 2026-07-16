package memorystoreoauth

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
)

func TestMemoryAuthCodeStore_IssueConsume(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemoryAuthCodeStore()

	info := &oauth.AuthCode{UserID: "u-alice", ClientID: "c1", ExpiresAt: time.Now().Add(time.Minute)}
	if err := m.Issue(ctx, "code-1", info); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := m.Consume(ctx, "code-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.UserID != "u-alice" {
		t.Errorf("UserID = %q, want u-alice", got.UserID)
	}
	if _, err := m.Consume(ctx, "code-1"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("double consume = %v, want ErrAuthCodeNotFound", err)
	}
}

// TestMemoryAuthCodeStore_MaxEntriesRejectsAtCapacity proves the opt-in
// MaxEntries cap rejects a new code once the store is full, and that
// consuming a code frees up room again.
func TestMemoryAuthCodeStore_MaxEntriesRejectsAtCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemoryAuthCodeStore()
	m.MaxEntries = 2
	future := time.Now().Add(time.Minute)

	if err := m.Issue(ctx, "code-1", &oauth.AuthCode{ExpiresAt: future}); err != nil {
		t.Fatalf("Issue 1: %v", err)
	}
	if err := m.Issue(ctx, "code-2", &oauth.AuthCode{ExpiresAt: future}); err != nil {
		t.Fatalf("Issue 2: %v", err)
	}
	if err := m.Issue(ctx, "code-3", &oauth.AuthCode{ExpiresAt: future}); !errors.Is(err, ErrStoreAtCapacity) {
		t.Fatalf("Issue 3 (over capacity) = %v, want ErrStoreAtCapacity", err)
	}

	if _, err := m.Consume(ctx, "code-1"); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if err := m.Issue(ctx, "code-4", &oauth.AuthCode{ExpiresAt: future}); err != nil {
		t.Fatalf("Issue after freeing a slot: %v", err)
	}
}

// TestMemoryAuthCodeStore_MaxEntriesZeroIsUnbounded proves the default
// (MaxEntries unset) never rejects an Issue.
func TestMemoryAuthCodeStore_MaxEntriesZeroIsUnbounded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemoryAuthCodeStore()
	future := time.Now().Add(time.Minute)
	for i := 0; i < 50; i++ {
		if err := m.Issue(ctx, "code-"+strconv.Itoa(i), &oauth.AuthCode{ExpiresAt: future}); err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
	}
}

// TestMemoryAuthCodeStore_ReaperSweepsExpiredCodes proves StartReaper
// removes an expired, never-consumed code, and that Close stops the sweep
// loop cleanly.
func TestMemoryAuthCodeStore_ReaperSweepsExpiredCodes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemoryAuthCodeStore()
	defer func() { _ = m.Close() }()

	if err := m.Issue(ctx, "code-1", &oauth.AuthCode{ExpiresAt: time.Now().Add(time.Millisecond)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	time.Sleep(5 * time.Millisecond) // let it expire

	m.StartReaper(5 * time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for m.entries.Len() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("expired code never swept from the store")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
