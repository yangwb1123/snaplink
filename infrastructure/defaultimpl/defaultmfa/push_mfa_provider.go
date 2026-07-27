package defaultmfa

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/spi"
)

// PushMFAProvider is the reference push-notification MFA factor.
// Implements both spi.MFAProvider and spi.MFABeginner.
type PushMFAProvider struct {
	store        PushApprovalStore
	transport    PushTransport
	pollInterval time.Duration
	maxWait      time.Duration

	// waiters is the per-approval-id wakeup registry. nil unless
	// WithPushChannelNotify opted in.
	waiters *pushWaiterRegistry
}

// PushMFAOption tunes the provider.
type PushMFAOption func(*PushMFAProvider)

// WithPushPollInterval sets the inter-poll sleep.
func WithPushPollInterval(d time.Duration) PushMFAOption {
	return func(p *PushMFAProvider) {
		if d > 0 {
			p.pollInterval = d
		}
	}
}

// WithPushMaxWait sets the Verify timeout.
func WithPushMaxWait(d time.Duration) PushMFAOption {
	return func(p *PushMFAProvider) {
		if d > 0 {
			p.maxWait = d
		}
	}
}

// WithPushChannelNotify enables the built-in channel-based wakeup fast path.
func WithPushChannelNotify() PushMFAOption {
	return func(p *PushMFAProvider) {
		if p.waiters == nil {
			p.waiters = newPushWaiterRegistry()
		}
	}
}

// NewPushMFAProvider validates + returns the provider.
func NewPushMFAProvider(store PushApprovalStore, transport PushTransport, opts ...PushMFAOption) (*PushMFAProvider, error) {
	if store == nil {
		return nil, errors.New("push_mfa: PushApprovalStore required")
	}
	if transport == nil {
		return nil, errors.New("push_mfa: PushTransport required")
	}
	p := &PushMFAProvider{
		store:        store,
		transport:    transport,
		pollInterval: 1 * time.Second,
		maxWait:      60 * time.Second,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// SupportedMethods returns ["push"].
func (p *PushMFAProvider) SupportedMethods() []string {
	return []string{MethodPush}
}

// Begin issues an approval id, persists a PENDING entry, calls the transport.
func (p *PushMFAProvider) Begin(ctx context.Context, subjectID, method string) (map[string]string, error) {
	if method != MethodPush {
		return nil, ErrPushUnsupportedMethod
	}
	if subjectID == "" {
		return nil, ErrPushMissingSubject
	}
	id, err := newPushApprovalID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	approval := &PushApproval{
		ID:        id,
		SubjectID: subjectID,
		Status:    PushApprovalPending,
		CreatedAt: now,
		ExpiresAt: now.Add(p.maxWait * 2),
	}
	if err := p.store.Put(ctx, approval); err != nil {
		return nil, err
	}
	if err := p.transport.Send(ctx, id, subjectID, nil); err != nil {
		_ = p.store.Delete(ctx, id)
		return nil, err
	}
	return map[string]string{"approval_id": id}, nil
}

// Verify waits for the approval id to resolve, or until maxWait elapses.
func (p *PushMFAProvider) Verify(ctx context.Context, subjectID, method string, params map[string]string) error {
	if method != MethodPush {
		return ErrPushUnsupportedMethod
	}
	if subjectID == "" {
		return ErrPushMissingSubject
	}
	id := params["approval_id"]
	if id == "" {
		return ErrPushMissingApprovalID
	}

	var wake <-chan struct{}
	if p.waiters != nil {
		var unregister func()
		wake, unregister = p.waiters.register(id)
		defer unregister()
	}

	deadline := time.Now().Add(p.maxWait)
	for {
		done, err := p.checkApproval(ctx, id, subjectID, deadline)
		if done {
			return err
		}
		timer := time.NewTimer(p.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// checkApproval performs one poll: loads the approval, validates the
// subject, and resolves the terminal states (approved/denied/timeout),
// deleting the entry on each. It returns done=true with the final error
// (nil on approval) when Verify must stop, or done=false to keep polling.
// A store load error is terminal and surfaces unchanged to the caller.
func (p *PushMFAProvider) checkApproval(ctx context.Context, id, subjectID string, deadline time.Time) (bool, error) {
	approval, err := p.store.Get(ctx, id)
	if err != nil {
		return true, err
	}
	if approval.SubjectID != subjectID {
		return true, ErrPushSubjectMismatch
	}
	switch approval.Status {
	case PushApprovalApproved:
		_ = p.store.Delete(ctx, id)
		return true, nil
	case PushApprovalDenied:
		_ = p.store.Delete(ctx, id)
		return true, ErrPushApprovalDenied
	}
	if time.Since(deadline) > 0 {
		_ = p.store.Delete(ctx, id)
		return true, ErrPushApprovalTimeout
	}
	return false, nil
}

// Notify wakes any Verify currently blocked on approvalID.
func (p *PushMFAProvider) Notify(approvalID string) {
	if p.waiters == nil || approvalID == "" {
		return
	}
	p.waiters.notify(approvalID)
}

// pushWaiterRegistry maps an approval id to the set of channels of
// Verify calls currently parked on it.
type pushWaiterRegistry struct {
	mu      sync.Mutex
	waiters map[string][]chan struct{}
}

func newPushWaiterRegistry() *pushWaiterRegistry {
	return &pushWaiterRegistry{waiters: make(map[string][]chan struct{})}
}

func (r *pushWaiterRegistry) register(id string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	r.mu.Lock()
	r.waiters[id] = append(r.waiters[id], ch)
	r.mu.Unlock()

	var once sync.Once
	unregister := func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			chans := r.waiters[id]
			for i, c := range chans {
				if c == ch {
					chans[i] = chans[len(chans)-1]
					r.waiters[id] = chans[:len(chans)-1]
					break
				}
			}
			if len(r.waiters[id]) == 0 {
				delete(r.waiters, id)
			}
		})
	}
	return ch, unregister
}

func (r *pushWaiterRegistry) notify(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ch := range r.waiters[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Interface guards.
var (
	_ spi.MFAProvider = (*PushMFAProvider)(nil)
	_ spi.MFABeginner = (*PushMFAProvider)(nil)
)
