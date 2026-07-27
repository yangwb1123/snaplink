package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
)

func deviceCodeDSN(t *testing.T) string {
	t.Helper()
	return "file:" + filepath.Join(t.TempDir(), "dc.db") + "?_journal=WAL"
}

func TestSQLiteDeviceCodeStore_IssueAndGetByDeviceCode(t *testing.T) {
	ctx := context.Background()
	store, err := NewDeviceCodeStore(deviceCodeDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceCodeStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	dc := &oauth.DeviceCode{
		DeviceCode: "dc-1",
		UserCode:   "ABCD-1234",
		ClientID:   "client-1",
		Scopes:     []string{"openid", "profile"},
		ExpiresAt:  time.Now().Add(time.Hour),
		Interval:   5 * time.Second,
	}
	if err := store.Issue(ctx, dc); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	got, err := store.GetByDeviceCode(ctx, "dc-1")
	if err != nil {
		t.Fatalf("GetByDeviceCode: %v", err)
	}
	if got.UserCode != "ABCD-1234" {
		t.Errorf("expected UserCode ABCD-1234, got %s", got.UserCode)
	}
	if got.Interval != 5*time.Second {
		t.Errorf("expected Interval 5s, got %v", got.Interval)
	}
}

func TestSQLiteDeviceCodeStore_GetByUserCode(t *testing.T) {
	ctx := context.Background()
	store, err := NewDeviceCodeStore(deviceCodeDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceCodeStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	_ = store.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "dc-2",
		UserCode:   "WXYZ-5678",
		ClientID:   "client-1",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	got, err := store.GetByUserCode(ctx, "WXYZ-5678")
	if err != nil {
		t.Fatalf("GetByUserCode: %v", err)
	}
	if got.DeviceCode != "dc-2" {
		t.Errorf("expected DeviceCode dc-2, got %s", got.DeviceCode)
	}
}

func TestSQLiteDeviceCodeStore_GetByUserCodeNotFound(t *testing.T) {
	ctx := context.Background()
	store, err := NewDeviceCodeStore(deviceCodeDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceCodeStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	_, err = store.GetByUserCode(ctx, "NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for nonexistent user code")
	}
}

func TestSQLiteDeviceCodeStore_Approve(t *testing.T) {
	ctx := context.Background()
	store, err := NewDeviceCodeStore(deviceCodeDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceCodeStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	_ = store.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "dc-approve",
		UserCode:   "APPROVE-01",
		ClientID:   "client-1",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	err = store.Approve(ctx, "APPROVE-01", "user-alice", "password", map[string]string{"email": "alice@test.com"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	got, err := store.GetByDeviceCode(ctx, "dc-approve")
	if err != nil {
		t.Fatalf("GetByDeviceCode: %v", err)
	}
	if !got.Approved {
		t.Error("expected Approved=true")
	}
	if got.UserID != "user-alice" {
		t.Errorf("expected UserID 'user-alice', got '%s'", got.UserID)
	}
	if got.Provider != "password" {
		t.Errorf("expected Provider 'password', got '%s'", got.Provider)
	}
}

func TestSQLiteDeviceCodeStore_Deny(t *testing.T) {
	ctx := context.Background()
	store, err := NewDeviceCodeStore(deviceCodeDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceCodeStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	_ = store.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "dc-deny",
		UserCode:   "DENY-01",
		ClientID:   "client-1",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	err = store.Deny(ctx, "DENY-01")
	if err != nil {
		t.Fatalf("Deny: %v", err)
	}

	got, err := store.GetByDeviceCode(ctx, "dc-deny")
	if err != nil {
		t.Fatalf("GetByDeviceCode: %v", err)
	}
	if !got.Denied {
		t.Error("expected Denied=true")
	}
}

func TestSQLiteDeviceCodeStore_Delete(t *testing.T) {
	ctx := context.Background()
	store, err := NewDeviceCodeStore(deviceCodeDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceCodeStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	_ = store.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "dc-delete",
		UserCode:   "DELETE-01",
		ClientID:   "client-1",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	err = store.Delete(ctx, "dc-delete")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = store.GetByDeviceCode(ctx, "dc-delete")
	if err == nil {
		t.Error("expected error after Delete")
	}
}

func TestSQLiteDeviceCodeStore_UpdateLastPoll(t *testing.T) {
	ctx := context.Background()
	store, err := NewDeviceCodeStore(deviceCodeDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceCodeStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	_ = store.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "dc-poll-ts",
		UserCode:   "POLL-TS",
		ClientID:   "client-1",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	pollTime := time.Now()
	err = store.UpdateLastPoll(ctx, "dc-poll-ts", pollTime)
	if err != nil {
		t.Fatalf("UpdateLastPoll: %v", err)
	}

	got, err := store.GetByDeviceCode(ctx, "dc-poll-ts")
	if err != nil {
		t.Fatalf("GetByDeviceCode: %v", err)
	}
	if got.LastPoll.IsZero() {
		t.Error("expected LastPoll to be set")
	}
}

func TestSQLiteDeviceCodeStore_ConsumeIfApproved(t *testing.T) {
	ctx := context.Background()
	store, err := NewDeviceCodeStore(deviceCodeDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceCodeStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	_ = store.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "dc-consume",
		UserCode:   "CONSUME-01",
		ClientID:   "client-1",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	// Not approved yet — ConsumeIfApproved should fail
	_, err = store.ConsumeIfApproved(ctx, "dc-consume")
	if err == nil {
		t.Error("expected error for unapproved code")
	}

	// Approve
	_ = store.Approve(ctx, "CONSUME-01", "user", "password", nil)

	// Now it should succeed
	consumed, err := store.ConsumeIfApproved(ctx, "dc-consume")
	if err != nil {
		t.Fatalf("ConsumeIfApproved after approve: %v", err)
	}
	if !consumed.Approved {
		t.Error("expected consumed code to be approved")
	}

	// Second consume should fail (already consumed/approved)
	_, err = store.ConsumeIfApproved(ctx, "dc-consume")
	if err == nil {
		t.Error("expected error on second consume")
	}
}

func TestSQLiteDeviceCodeStore_Resources(t *testing.T) {
	ctx := context.Background()
	store, err := NewDeviceCodeStore(deviceCodeDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceCodeStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	_ = store.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "dc-res",
		UserCode:   "RES-01",
		ClientID:   "client-1",
		ExpiresAt:  time.Now().Add(time.Hour),
		Resources:  []string{"https://api.example.com/resource1", "https://api.example.com/resource2"},
	})

	got, err := store.GetByDeviceCode(ctx, "dc-res")
	if err != nil {
		t.Fatalf("GetByDeviceCode: %v", err)
	}
	if len(got.Resources) != 2 {
		t.Errorf("expected 2 resources, got %d", len(got.Resources))
	}
}

func TestSQLiteDeviceCodeStore_ExpiredCodeUnreachable(t *testing.T) {
	ctx := context.Background()
	store, err := NewDeviceCodeStore(deviceCodeDSN(t))
	if err != nil {
		t.Fatalf("NewDeviceCodeStore: %v", err)
	}
	t.Cleanup(func() { store.db.Close() })

	_ = store.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "dc-expired",
		UserCode:   "EXPIRED-01",
		ClientID:   "client-1",
		ExpiresAt:  time.Now().Add(-time.Hour),
	})

	// GetByDeviceCode filters out expired codes — should return not-found
	_, err = store.GetByDeviceCode(ctx, "dc-expired")
	if err == nil {
		t.Error("expected error for expired device code")
	} else if err == oauth.ErrDeviceCodeNotFound {
		t.Log("expired code correctly hidden by GetByDeviceCode")
	} else {
		t.Logf("expired code error: %v", err)
	}
}
