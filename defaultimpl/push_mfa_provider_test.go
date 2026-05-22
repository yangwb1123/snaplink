package defaultimpl_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/defaultimpl"
)

// captureTransport records every Send call so tests can assert
// delivery semantics without a real FCM/APNs SDK.
type captureTransport struct {
	mu    sync.Mutex
	calls []struct {
		ID, Subject string
		Meta        map[string]string
	}
	sendErr error
}

func (c *captureTransport) Send(_ context.Context, id, subject string, meta map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, struct {
		ID, Subject string
		Meta        map[string]string
	}{ID: id, Subject: subject, Meta: meta})
	return c.sendErr
}

func (c *captureTransport) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

func newPushProviderForTest(t *testing.T, opts ...defaultimpl.PushMFAOption) (*defaultimpl.PushMFAProvider, *defaultimpl.MemoryPushApprovalStore, *captureTransport) {
	t.Helper()
	store := defaultimpl.NewMemoryPushApprovalStore()
	transport := &captureTransport{}
	// Default to fast polling so tests don't sleep for seconds.
	defaults := []defaultimpl.PushMFAOption{
		defaultimpl.WithPushPollInterval(10 * time.Millisecond),
		defaultimpl.WithPushMaxWait(500 * time.Millisecond),
	}
	p, err := defaultimpl.NewPushMFAProvider(store, transport, append(defaults, opts...)...)
	if err != nil {
		t.Fatalf("NewPushMFAProvider: %v", err)
	}
	return p, store, transport
}

func TestPushMFAProvider_RejectsNilStore(t *testing.T) {
	if _, err := defaultimpl.NewPushMFAProvider(nil, &captureTransport{}); err == nil {
		t.Fatal("want error for nil store")
	}
}

func TestPushMFAProvider_RejectsNilTransport(t *testing.T) {
	if _, err := defaultimpl.NewPushMFAProvider(defaultimpl.NewMemoryPushApprovalStore(), nil); err == nil {
		t.Fatal("want error for nil transport")
	}
}

func TestPushMFAProvider_SupportedMethods(t *testing.T) {
	p, _, _ := newPushProviderForTest(t)
	methods := p.SupportedMethods()
	if len(methods) != 1 || methods[0] != defaultimpl.MethodPush {
		t.Fatalf("SupportedMethods = %v, want [push]", methods)
	}
}

func TestPushMFAProvider_BeginIssuesPendingApprovalAndSendsTransport(t *testing.T) {
	p, store, transport := newPushProviderForTest(t)
	ctx := context.Background()

	data, err := p.Begin(ctx, "alice", defaultimpl.MethodPush)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	id := data["approval_id"]
	if id == "" {
		t.Fatalf("Begin returned no approval_id; data=%v", data)
	}
	if transport.Calls() != 1 {
		t.Errorf("transport called %d times, want 1", transport.Calls())
	}
	// Approval should be persisted as PENDING.
	approval, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if approval.Status != defaultimpl.PushApprovalPending {
		t.Errorf("status = %v, want pending", approval.Status)
	}
	if approval.SubjectID != "alice" {
		t.Errorf("subjectID = %v, want alice", approval.SubjectID)
	}
}

func TestPushMFAProvider_BeginRejectsUnsupportedMethod(t *testing.T) {
	p, _, _ := newPushProviderForTest(t)
	_, err := p.Begin(context.Background(), "alice", "totp")
	if !errors.Is(err, defaultimpl.ErrPushUnsupportedMethod) {
		t.Fatalf("got %v, want ErrPushUnsupportedMethod", err)
	}
}

func TestPushMFAProvider_BeginRejectsEmptySubject(t *testing.T) {
	p, _, _ := newPushProviderForTest(t)
	_, err := p.Begin(context.Background(), "", defaultimpl.MethodPush)
	if !errors.Is(err, defaultimpl.ErrPushMissingSubject) {
		t.Fatalf("got %v, want ErrPushMissingSubject", err)
	}
}

func TestPushMFAProvider_BeginCleansUpOnTransportFailure(t *testing.T) {
	store := defaultimpl.NewMemoryPushApprovalStore()
	transport := &captureTransport{sendErr: errors.New("transport down")}
	p, err := defaultimpl.NewPushMFAProvider(store, transport,
		defaultimpl.WithPushPollInterval(10*time.Millisecond),
		defaultimpl.WithPushMaxWait(500*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := p.Begin(context.Background(), "alice", defaultimpl.MethodPush); err == nil {
		t.Fatal("want error when transport fails")
	}
	// No dangling PENDING entry — operators investigating store
	// state after a transport outage shouldn't see ghost approvals
	// that consume their cron's expiry-sweep budget.
	if transport.Calls() != 1 {
		t.Errorf("transport.Calls() = %d, want 1", transport.Calls())
	}
}

func TestPushMFAProvider_VerifyApprovedSucceeds(t *testing.T) {
	p, store, _ := newPushProviderForTest(t)
	ctx := context.Background()

	data, err := p.Begin(ctx, "alice", defaultimpl.MethodPush)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	id := data["approval_id"]

	// Async approval — same pattern as a device callback.
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = store.SetStatus(ctx, id, defaultimpl.PushApprovalApproved)
	}()

	err = p.Verify(ctx, "alice", defaultimpl.MethodPush, map[string]string{"approval_id": id})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Anti-replay: approval should be deleted post-Verify.
	if _, err := store.Get(ctx, id); !errors.Is(err, defaultimpl.ErrPushApprovalNotFound) {
		t.Errorf("post-Verify Get: got %v, want ErrPushApprovalNotFound", err)
	}
}

func TestPushMFAProvider_VerifyDeniedReturnsDenied(t *testing.T) {
	p, store, _ := newPushProviderForTest(t)
	ctx := context.Background()

	data, _ := p.Begin(ctx, "alice", defaultimpl.MethodPush)
	id := data["approval_id"]

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = store.SetStatus(ctx, id, defaultimpl.PushApprovalDenied)
	}()

	err := p.Verify(ctx, "alice", defaultimpl.MethodPush, map[string]string{"approval_id": id})
	if !errors.Is(err, defaultimpl.ErrPushApprovalDenied) {
		t.Fatalf("got %v, want ErrPushApprovalDenied", err)
	}
}

func TestPushMFAProvider_VerifyTimesOutWhenNoApproval(t *testing.T) {
	// 100ms maxWait — finishes within test budget.
	p, store, _ := newPushProviderForTest(t,
		defaultimpl.WithPushPollInterval(20*time.Millisecond),
		defaultimpl.WithPushMaxWait(100*time.Millisecond),
	)
	ctx := context.Background()

	data, _ := p.Begin(ctx, "alice", defaultimpl.MethodPush)
	id := data["approval_id"]

	err := p.Verify(ctx, "alice", defaultimpl.MethodPush, map[string]string{"approval_id": id})
	if !errors.Is(err, defaultimpl.ErrPushApprovalTimeout) {
		t.Fatalf("got %v, want ErrPushApprovalTimeout", err)
	}
	// Timed-out entry should be cleaned up.
	if _, err := store.Get(ctx, id); !errors.Is(err, defaultimpl.ErrPushApprovalNotFound) {
		t.Errorf("post-timeout Get: got %v, want ErrPushApprovalNotFound", err)
	}
}

func TestPushMFAProvider_VerifyRespectsContextCancel(t *testing.T) {
	p, _, _ := newPushProviderForTest(t,
		defaultimpl.WithPushMaxWait(10*time.Second), // long timeout — would block test
	)
	ctx, cancel := context.WithCancel(context.Background())
	data, _ := p.Begin(ctx, "alice", defaultimpl.MethodPush)
	id := data["approval_id"]

	var verifyErr atomic.Value
	done := make(chan struct{})
	go func() {
		err := p.Verify(ctx, "alice", defaultimpl.MethodPush, map[string]string{"approval_id": id})
		verifyErr.Store(err)
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Verify didn't return after ctx cancel")
	}
	if err, _ := verifyErr.Load().(error); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestPushMFAProvider_VerifyRejectsSubjectMismatch(t *testing.T) {
	p, store, _ := newPushProviderForTest(t)
	ctx := context.Background()

	// alice issued the approval...
	data, _ := p.Begin(ctx, "alice", defaultimpl.MethodPush)
	id := data["approval_id"]
	_ = store.SetStatus(ctx, id, defaultimpl.PushApprovalApproved)

	// ...but mallory tries to Verify with alice's id.
	err := p.Verify(ctx, "mallory", defaultimpl.MethodPush, map[string]string{"approval_id": id})
	if !errors.Is(err, defaultimpl.ErrPushSubjectMismatch) {
		t.Fatalf("got %v, want ErrPushSubjectMismatch", err)
	}
}

func TestPushMFAProvider_VerifyRejectsMissingApprovalID(t *testing.T) {
	p, _, _ := newPushProviderForTest(t)
	err := p.Verify(context.Background(), "alice", defaultimpl.MethodPush, nil)
	if !errors.Is(err, defaultimpl.ErrPushMissingApprovalID) {
		t.Fatalf("got %v, want ErrPushMissingApprovalID", err)
	}
}

func TestPushMFAProvider_VerifyRejectsUnsupportedMethod(t *testing.T) {
	p, _, _ := newPushProviderForTest(t)
	err := p.Verify(context.Background(), "alice", "totp", map[string]string{"approval_id": "x"})
	if !errors.Is(err, defaultimpl.ErrPushUnsupportedMethod) {
		t.Fatalf("got %v, want ErrPushUnsupportedMethod", err)
	}
}

// ---- MemoryPushApprovalStore ----

func TestMemoryPushApprovalStore_PutRejectsEmptyID(t *testing.T) {
	s := defaultimpl.NewMemoryPushApprovalStore()
	err := s.Put(context.Background(), &defaultimpl.PushApproval{SubjectID: "alice", ExpiresAt: time.Now().Add(time.Minute)})
	if !errors.Is(err, defaultimpl.ErrPushApprovalInvalid) {
		t.Fatalf("got %v, want ErrPushApprovalInvalid", err)
	}
}

func TestMemoryPushApprovalStore_PutRejectsEmptySubject(t *testing.T) {
	s := defaultimpl.NewMemoryPushApprovalStore()
	err := s.Put(context.Background(), &defaultimpl.PushApproval{ID: "id", ExpiresAt: time.Now().Add(time.Minute)})
	if !errors.Is(err, defaultimpl.ErrPushApprovalInvalid) {
		t.Fatalf("got %v, want ErrPushApprovalInvalid", err)
	}
}

func TestMemoryPushApprovalStore_GetExpiredReturnsNotFound(t *testing.T) {
	s := defaultimpl.NewMemoryPushApprovalStore()
	_ = s.Put(context.Background(), &defaultimpl.PushApproval{
		ID:        "id",
		SubjectID: "alice",
		Status:    defaultimpl.PushApprovalPending,
		ExpiresAt: time.Now().Add(-1 * time.Second),
	})
	_, err := s.Get(context.Background(), "id")
	if !errors.Is(err, defaultimpl.ErrPushApprovalNotFound) {
		t.Fatalf("got %v, want ErrPushApprovalNotFound", err)
	}
}

func TestMemoryPushApprovalStore_SetStatusRejectsReResolution(t *testing.T) {
	s := defaultimpl.NewMemoryPushApprovalStore()
	_ = s.Put(context.Background(), &defaultimpl.PushApproval{
		ID:        "id",
		SubjectID: "alice",
		Status:    defaultimpl.PushApprovalPending,
		ExpiresAt: time.Now().Add(time.Minute),
	})
	if err := s.SetStatus(context.Background(), "id", defaultimpl.PushApprovalApproved); err != nil {
		t.Fatalf("first SetStatus: %v", err)
	}
	// Trying to deny an already-approved entry is the suspicious case
	// operators want to see in audit. The store refuses.
	err := s.SetStatus(context.Background(), "id", defaultimpl.PushApprovalDenied)
	if !errors.Is(err, defaultimpl.ErrPushApprovalResolved) {
		t.Fatalf("got %v, want ErrPushApprovalResolved", err)
	}
}

func TestMemoryPushApprovalStore_SetStatusIdempotentForSameStatus(t *testing.T) {
	s := defaultimpl.NewMemoryPushApprovalStore()
	_ = s.Put(context.Background(), &defaultimpl.PushApproval{
		ID:        "id",
		SubjectID: "alice",
		Status:    defaultimpl.PushApprovalPending,
		ExpiresAt: time.Now().Add(time.Minute),
	})
	// Setting Pending → Pending should silently succeed (operators
	// retrying a callback shouldn't see errors on no-op transitions).
	if err := s.SetStatus(context.Background(), "id", defaultimpl.PushApprovalPending); err != nil {
		t.Fatalf("idempotent SetStatus: %v", err)
	}
}

func TestMemoryPushApprovalStore_DeleteIsIdempotent(t *testing.T) {
	s := defaultimpl.NewMemoryPushApprovalStore()
	if err := s.Delete(context.Background(), "nonexistent"); err != nil {
		t.Fatalf("Delete on missing id: %v", err)
	}
}
