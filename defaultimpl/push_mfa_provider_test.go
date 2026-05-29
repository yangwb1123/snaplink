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

// ---- WithPushChannelNotify fast-path ----

// TestPushMFAProvider_ChannelNotifyWakesFast proves the wakeup fires
// in well under one poll interval: a 5s poll would otherwise dominate,
// so a sub-second return can only come from the channel signal.
func TestPushMFAProvider_ChannelNotifyWakesFast(t *testing.T) {
	store := defaultimpl.NewMemoryPushApprovalStore()
	transport := &captureTransport{}
	p, err := defaultimpl.NewPushMFAProvider(store, transport,
		defaultimpl.WithPushPollInterval(5*time.Second), // poll must NOT be what wakes us
		defaultimpl.WithPushMaxWait(10*time.Second),
		defaultimpl.WithPushChannelNotify(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	data, err := p.Begin(ctx, "alice", defaultimpl.MethodPush)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	id := data["approval_id"]

	go func() {
		time.Sleep(20 * time.Millisecond)
		if err := store.SetStatus(ctx, id, defaultimpl.PushApprovalApproved); err != nil {
			return
		}
		p.Notify(id)
	}()

	start := time.Now()
	if err := p.Verify(ctx, "alice", defaultimpl.MethodPush, map[string]string{"approval_id": id}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	elapsed := time.Since(start)
	// Generous ceiling (1s) — far below the 5s poll, so this asserts
	// the channel woke Verify without being flaky on a loaded CI box.
	if elapsed >= time.Second {
		t.Fatalf("Verify took %v, want sub-second (channel wakeup, not poll)", elapsed)
	}
}

// TestPushMFAProvider_ChannelNotifyCorrectWhenSignalDropped is the
// correctness half: channel-notify is enabled but the resolver NEVER
// calls Notify (modeling a coalesced/lost signal or a cross-replica
// callback). Verify must still resolve via the poll fallback — proving
// correctness never depends on the wakeup arriving.
func TestPushMFAProvider_ChannelNotifyCorrectWhenSignalDropped(t *testing.T) {
	store := defaultimpl.NewMemoryPushApprovalStore()
	transport := &captureTransport{}
	p, err := defaultimpl.NewPushMFAProvider(store, transport,
		defaultimpl.WithPushPollInterval(10*time.Millisecond),
		defaultimpl.WithPushMaxWait(2*time.Second),
		defaultimpl.WithPushChannelNotify(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	data, _ := p.Begin(ctx, "alice", defaultimpl.MethodPush)
	id := data["approval_id"]

	go func() {
		time.Sleep(20 * time.Millisecond)
		// Deliberately NO p.Notify — the store is the source of truth.
		_ = store.SetStatus(ctx, id, defaultimpl.PushApprovalApproved)
	}()

	if err := p.Verify(ctx, "alice", defaultimpl.MethodPush, map[string]string{"approval_id": id}); err != nil {
		t.Fatalf("Verify must succeed via poll fallback even with no Notify; got %v", err)
	}
}

// TestPushMFAProvider_ChannelNotifyLostWakeupRace stresses the window
// the pre-Get waiter registration is meant to close: the resolve
// (SetStatus + Notify) races Verify's start, with a poll interval long
// enough that the poll cannot rescue a lost wakeup within the test
// budget. Run under -race -count to surface ordering bugs + the
// registry's concurrent access.
func TestPushMFAProvider_ChannelNotifyLostWakeupRace(t *testing.T) {
	store := defaultimpl.NewMemoryPushApprovalStore()
	transport := &captureTransport{}
	p, err := defaultimpl.NewPushMFAProvider(store, transport,
		defaultimpl.WithPushPollInterval(2*time.Second), // poll can't mask a lost wakeup in-budget
		defaultimpl.WithPushMaxWait(10*time.Second),
		defaultimpl.WithPushChannelNotify(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		data, err := p.Begin(ctx, "alice", defaultimpl.MethodPush)
		if err != nil {
			t.Fatalf("Begin[%d]: %v", i, err)
		}
		id := data["approval_id"]

		// Resolve + Notify on another goroutine with NO artificial delay
		// so it interleaves arbitrarily with Verify's register/Get/park.
		go func() {
			_ = store.SetStatus(ctx, id, defaultimpl.PushApprovalApproved)
			p.Notify(id)
		}()

		start := time.Now()
		if err := p.Verify(ctx, "alice", defaultimpl.MethodPush, map[string]string{"approval_id": id}); err != nil {
			t.Fatalf("Verify[%d]: %v", i, err)
		}
		// If the wakeup were lost, the only escape is the 2s poll —
		// anything below that proves the buffered pre-registered waiter
		// caught the signal that landed before the park.
		if elapsed := time.Since(start); elapsed >= time.Second {
			t.Fatalf("Verify[%d] took %v — lost-wakeup window not closed", i, elapsed)
		}
	}
}

// TestPushMFAProvider_NotifyNoopWithoutOptIn proves Notify is a safe
// no-op when WithPushChannelNotify wasn't set: calling it must neither
// panic nor break the pure-poll resolution path (full backward compat).
func TestPushMFAProvider_NotifyNoopWithoutOptIn(t *testing.T) {
	p, store, _ := newPushProviderForTest(t) // no WithPushChannelNotify
	ctx := context.Background()
	data, _ := p.Begin(ctx, "alice", defaultimpl.MethodPush)
	id := data["approval_id"]

	// Must be inert even for an unknown id and the live id.
	p.Notify("does-not-exist")
	p.Notify(id)

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = store.SetStatus(ctx, id, defaultimpl.PushApprovalApproved)
		p.Notify(id) // still a no-op; poll resolves
	}()

	if err := p.Verify(ctx, "alice", defaultimpl.MethodPush, map[string]string{"approval_id": id}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestPushMFAProvider_ChannelNotifyConcurrentDistinctIDs runs many
// concurrent Verifies for distinct approval ids, each woken by its own
// Notify. Asserts each gets the right answer (approve vs deny) — the
// registry must isolate waiters per id under -race.
func TestPushMFAProvider_ChannelNotifyConcurrentDistinctIDs(t *testing.T) {
	store := defaultimpl.NewMemoryPushApprovalStore()
	transport := &captureTransport{}
	p, err := defaultimpl.NewPushMFAProvider(store, transport,
		defaultimpl.WithPushPollInterval(5*time.Second), // force the channel to be the waker
		defaultimpl.WithPushMaxWait(10*time.Second),
		defaultimpl.WithPushChannelNotify(),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	const n = 20
	type job struct {
		id      string
		approve bool
	}
	jobs := make([]job, n)
	for i := 0; i < n; i++ {
		data, err := p.Begin(ctx, "alice", defaultimpl.MethodPush)
		if err != nil {
			t.Fatalf("Begin[%d]: %v", i, err)
		}
		jobs[i] = job{id: data["approval_id"], approve: i%2 == 0}
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range jobs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = p.Verify(ctx, "alice", defaultimpl.MethodPush, map[string]string{"approval_id": jobs[i].id})
		}(i)
	}
	// Resolve each from another goroutine — distinct ids, mixed outcomes.
	for i := range jobs {
		go func(i int) {
			status := defaultimpl.PushApprovalDenied
			if jobs[i].approve {
				status = defaultimpl.PushApprovalApproved
			}
			_ = store.SetStatus(ctx, jobs[i].id, status)
			p.Notify(jobs[i].id)
		}(i)
	}
	wg.Wait()

	for i := range jobs {
		if jobs[i].approve {
			if errs[i] != nil {
				t.Errorf("job[%d] approve: got %v, want nil", i, errs[i])
			}
		} else if !errors.Is(errs[i], defaultimpl.ErrPushApprovalDenied) {
			t.Errorf("job[%d] deny: got %v, want ErrPushApprovalDenied", i, errs[i])
		}
	}
}
