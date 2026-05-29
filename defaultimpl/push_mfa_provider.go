package defaultimpl

import "github.com/snaplink/sso/spi"

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// MethodPush is the canonical wire name for the push-notification
// factor in /auth/mfa request bodies and mfa_methods arrays. Stable
// across versions so SPAs branch on this constant.
const MethodPush = "push"

// PushApprovalStatus is the lifecycle a single push approval flows
// through. State transitions are driven externally: a transport
// (FCM/APNs/webhook) delivers the approval id to the user's device;
// the device app POSTs Approve or Deny back to the SSO server's
// (operator-supplied) callback handler, which calls
// PushApprovalStore.SetStatus to advance the entry. The MFA Verify
// then polls — or, when the callback also calls
// [PushMFAProvider.Notify] (opt-in via [WithPushChannelNotify]), the
// blocked Verify wakes immediately on the next channel signal.
type PushApprovalStatus string

const (
	// PushApprovalPending — Begin issued the approval; the user
	// hasn't responded yet.
	PushApprovalPending PushApprovalStatus = "pending"
	// PushApprovalApproved — user tapped Approve. Verify returns nil.
	PushApprovalApproved PushApprovalStatus = "approved"
	// PushApprovalDenied — user tapped Deny. Verify returns
	// ErrPushApprovalDenied.
	PushApprovalDenied PushApprovalStatus = "denied"
)

// PushApproval is one in-flight push approval. Bound to a single
// (SubjectID, ApprovalID) pair, single-resolve, short-lived
// (operator-tunable per challenge TTL on the SSO server).
type PushApproval struct {
	ID        string
	SubjectID string
	Status    PushApprovalStatus
	CreatedAt time.Time
	ExpiresAt time.Time
}

// PushApprovalStore persists push approvals between Begin (issuance
// at /auth/login MFA dispatch) and Verify (consumption at
// /auth/mfa). The provider doesn't drive the lifecycle directly —
// an operator-supplied push transport delivers the approval id to
// the user's device, and the device replies via a separate
// (operator-built) callback HTTP endpoint that calls SetStatus.
//
// Put / Get are sufficient for the polling variant of Verify.
// Channel-based notification (so Verify wakes immediately instead of
// waiting out a poll tick) ships built-in + opt-in via
// [WithPushChannelNotify] — see [PushMFAProvider.Notify]. The store
// stays the authoritative source of truth either way; the channel is
// only a latency hint.
type PushApprovalStore interface {
	// Put persists a freshly-issued PENDING approval. ID + SubjectID
	// + ExpiresAt MUST be set; the store rejects ID="" with
	// ErrPushApprovalInvalid.
	Put(ctx context.Context, a *PushApproval) error

	// Get returns the current approval. Missing / expired entries
	// surface as ErrPushApprovalNotFound (anti-enumeration parity
	// with MFAChallengeStore).
	Get(ctx context.Context, id string) (*PushApproval, error)

	// SetStatus transitions an entry from Pending to either Approved
	// or Denied. Operator-supplied callback handlers (POST
	// /push/approval/{id}/{decision}) wire this. Idempotent for
	// matching transitions; refuses status changes for an already-
	// resolved approval (operators investigating audit see a clean
	// "approve then deny" attempt).
	SetStatus(ctx context.Context, id string, status PushApprovalStatus) error

	// Delete removes an entry — operators run this on approval
	// expiry from a cron, or implicitly via Get's expiry sweep when
	// supported.
	Delete(ctx context.Context, id string) error
}

// PushTransport is the operator-supplied push delivery shim. The
// provider's Begin calls Send with the approval id + subject + an
// opaque map of metadata (operator's choice — message text,
// localization hints, deeplink URL the device app should render).
// Returns nil on successful enqueue (NOT on user response — that's
// the callback's job); transport errors propagate from Begin.
type PushTransport interface {
	Send(ctx context.Context, approvalID, subjectID string, metadata map[string]string) error
}

// PushTransportFunc is a function adapter for PushTransport.
type PushTransportFunc func(ctx context.Context, approvalID, subjectID string, metadata map[string]string) error

// Send implements PushTransport.
func (f PushTransportFunc) Send(ctx context.Context, approvalID, subjectID string, metadata map[string]string) error {
	return f(ctx, approvalID, subjectID, metadata)
}

// PushMFAProvider is the reference push-notification MFA factor.
// Implements both [spi.MFAProvider] and [spi.MFABeginner] — Begin
// issues a fresh approval id, calls the transport to deliver it,
// and returns the approval id under mfa_method_data["push"]
// {approval_id: <id>}; Verify polls the PushApprovalStore until
// the approval resolves (approved / denied / expires).
//
// Polling is the default to keep the Verify SPI synchronous and the
// store the single source of truth. Opt into the channel-based fast
// path with [WithPushChannelNotify]: the approval callback then calls
// [PushMFAProvider.Notify] right after SetStatus, waking a blocked
// Verify in milliseconds instead of after a full poll tick. The
// channel is a pure latency HINT — Verify always re-reads the store
// before acting, so a dropped/missed signal degrades to the poll
// cadence rather than to a wrong answer (see Verify).
type PushMFAProvider struct {
	store        PushApprovalStore
	transport    PushTransport
	pollInterval time.Duration
	maxWait      time.Duration

	// waiters is the per-approval-id wakeup registry. nil unless
	// WithPushChannelNotify opted in — keeping the default path a
	// pure poll with zero extra allocation or locking.
	waiters *pushWaiterRegistry
}

// PushMFAOption tunes the provider. Sane defaults: poll every 1s,
// wait at most 60s for user response.
type PushMFAOption func(*PushMFAProvider)

// WithPushPollInterval sets the inter-poll sleep. Lower = faster
// user feedback at the cost of more PushApprovalStore reads.
func WithPushPollInterval(d time.Duration) PushMFAOption {
	return func(p *PushMFAProvider) {
		if d > 0 {
			p.pollInterval = d
		}
	}
}

// WithPushMaxWait sets the Verify timeout. Operators should pair
// this with the MFAChallengeStore's challenge TTL — the push wait
// cannot exceed the parent challenge's expiry.
func WithPushMaxWait(d time.Duration) PushMFAOption {
	return func(p *PushMFAProvider) {
		if d > 0 {
			p.maxWait = d
		}
	}
}

// WithPushChannelNotify enables the built-in channel-based wakeup
// fast path. With it set, the approval callback (the handler that
// calls SetStatus) SHOULD also call [PushMFAProvider.Notify] with the
// resolved approval id — a blocked Verify then returns within
// milliseconds instead of after a poll tick. Without it, Verify keeps
// the historical pure-poll behavior (and Notify is a no-op), so this
// is fully backward-compatible.
//
// Correctness never depends on the signal arriving: Verify re-reads
// the authoritative store on every wakeup AND on the poll fallback,
// so a coalesced/dropped Notify only costs latency, not a wrong
// verification result.
func WithPushChannelNotify() PushMFAOption {
	return func(p *PushMFAProvider) {
		if p.waiters == nil {
			p.waiters = newPushWaiterRegistry()
		}
	}
}

// NewPushMFAProvider validates + returns the provider. store +
// transport are required; nil → constructor error.
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

// Begin issues an approval id, persists a PENDING entry, calls the
// transport to deliver it. Returns the approval id under
// {"approval_id": "<id>"} so the client SPA can poll (or display
// "waiting for device" UX).
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
	// Store-level ExpiresAt is the BACKSTOP for the Verify-level
	// timeout — set it well beyond maxWait so the Verify deadline
	// fires first (operators see ErrPushApprovalTimeout) rather than
	// racing the store's expiry sweep (which would surface
	// ErrPushApprovalNotFound and confuse operators about whether
	// the approval was ever issued). The store still prunes via its
	// own expiry; this just nudges the boundary so the wire-visible
	// error is always the timeout.
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
		// Cleanup the persisted PENDING entry — operators don't want
		// dangling approvals when the transport refuses delivery.
		_ = p.store.Delete(ctx, id)
		return nil, err
	}
	return map[string]string{"approval_id": id}, nil
}

// Verify waits for the approval id to resolve, or until maxWait
// elapses. Approved → nil; Denied → ErrPushApprovalDenied; expiry
// or missing → ErrPushApprovalNotFound (the SDK collapses both to
// mfa_invalid). Caller ctx cancellation is honored.
//
// Default behavior polls the store every pollInterval. When
// [WithPushChannelNotify] is set, Verify ALSO parks on a per-id
// wakeup channel so a [Notify] call from the approval callback
// short-circuits the next poll tick.
//
// Lost-wakeup safety: the waiter is registered BEFORE the first store
// Get, so a decision (SetStatus + Notify) landing in the window
// between that Get and the park is retained by the channel's buffer
// and consumed on the very next park — Verify then re-reads the store
// and returns. The channel is only ever a hint to re-read sooner; the
// store read is authoritative, so a coalesced or missed signal costs
// at most one poll interval of latency.
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

	// Register the waiter BEFORE the first store read so we can't lose
	// a wakeup that fires between the read and the park. nil registry
	// (channel-notify not opted in) yields a nil channel, which select
	// silently ignores — collapsing to the pure-poll path.
	var wake <-chan struct{}
	if p.waiters != nil {
		var unregister func()
		wake, unregister = p.waiters.register(id)
		defer unregister()
	}

	deadline := time.Now().Add(p.maxWait)
	for {
		approval, err := p.store.Get(ctx, id)
		if err != nil {
			return err
		}
		if approval.SubjectID != subjectID {
			// Defense-in-depth: a stolen approval id can't be replayed
			// to authenticate someone else.
			return ErrPushSubjectMismatch
		}
		switch approval.Status {
		case PushApprovalApproved:
			// Delete on success so a future replay of the same params
			// payload hits ErrPushApprovalNotFound (anti-replay).
			_ = p.store.Delete(ctx, id)
			return nil
		case PushApprovalDenied:
			_ = p.store.Delete(ctx, id)
			return ErrPushApprovalDenied
		}
		if time.Now().After(deadline) {
			_ = p.store.Delete(ctx, id)
			return ErrPushApprovalTimeout
		}
		// Park until: ctx cancel, a Notify wakeup (channel-notify path),
		// or the poll tick (always-present fallback). Draining whichever
		// fires re-runs the loop and re-reads the authoritative store.
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

// Notify wakes any Verify currently blocked on approvalID so it
// re-reads the store immediately. It is the fast-path companion to
// [WithPushChannelNotify]: the approval callback calls it right after
// PushApprovalStore.SetStatus succeeds. Safe to call unconditionally —
// when channel-notify isn't enabled (or no Verify is parked on the
// id) it is a cheap no-op. Non-blocking: a slow/absent waiter never
// stalls the caller.
func (p *PushMFAProvider) Notify(approvalID string) {
	if p.waiters == nil || approvalID == "" {
		return
	}
	p.waiters.notify(approvalID)
}

// Sentinel errors. The SDK collapses every Verify failure to
// mfa_invalid on the wire (anti-enumeration); these provide
// operator-side observability via the mfa_failure audit reason.
var (
	ErrPushUnsupportedMethod = errors.New("push_mfa: unsupported method")
	ErrPushMissingSubject    = errors.New("push_mfa: missing subject")
	ErrPushMissingApprovalID = errors.New("push_mfa: missing approval id")
	ErrPushSubjectMismatch   = errors.New("push_mfa: subject mismatch")
	ErrPushApprovalNotFound  = errors.New("push_mfa: approval not found")
	ErrPushApprovalDenied    = errors.New("push_mfa: approval denied")
	ErrPushApprovalTimeout   = errors.New("push_mfa: approval timed out")
	ErrPushApprovalInvalid   = errors.New("push_mfa: invalid approval entry")
	ErrPushApprovalResolved  = errors.New("push_mfa: approval already resolved")
)

// pushWaiterRegistry maps an approval id to the set of channels of
// Verify calls currently parked on it. Each waiter owns a distinct
// buffered (cap-1) channel so notify is non-blocking AND a signal
// that arrives before the waiter parks is retained until the next
// park (this is what closes the lost-wakeup window). Multiple
// concurrent Verifies for the same id each register their own
// channel; notify fans out to all of them.
//
// The map only ever holds ids with at least one live waiter:
// register adds, the returned unregister removes (and drops the slice
// when it empties), so a flood of one-shot notifies for ids nobody is
// verifying leaves no residue.
type pushWaiterRegistry struct {
	mu      sync.Mutex
	waiters map[string][]chan struct{}
}

func newPushWaiterRegistry() *pushWaiterRegistry {
	return &pushWaiterRegistry{waiters: make(map[string][]chan struct{})}
}

// register adds a fresh waiter for id and returns its receive channel
// plus an idempotent unregister to call on Verify return (via defer).
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
					// Swap-remove: order among waiters is irrelevant.
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

// notify wakes every waiter parked on id. The per-waiter send is
// non-blocking: a cap-1 channel that already holds a pending signal
// (waiter not yet re-parked) is left as-is — the waiter will observe
// exactly one wakeup and re-read the store, which is all correctness
// needs.
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

// MemoryPushApprovalStore is a process-local PushApprovalStore.
// Single-replica dev / tests; cluster deploys should ship a
// SQLite (or Redis) peer so a Begin on replica A is resolvable on
// the replica handling the callback.
type MemoryPushApprovalStore struct {
	mu      sync.Mutex
	entries map[string]*PushApproval
}

// NewMemoryPushApprovalStore returns an empty in-process store.
func NewMemoryPushApprovalStore() *MemoryPushApprovalStore {
	return &MemoryPushApprovalStore{entries: make(map[string]*PushApproval)}
}

// Put persists a freshly-issued approval. Caller MUST set ID +
// SubjectID; ID="" → ErrPushApprovalInvalid.
func (m *MemoryPushApprovalStore) Put(_ context.Context, a *PushApproval) error {
	if a == nil || a.ID == "" || a.SubjectID == "" {
		return ErrPushApprovalInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *a
	m.entries[a.ID] = &cp
	return nil
}

// Get returns the approval; missing / expired → ErrPushApprovalNotFound.
func (m *MemoryPushApprovalStore) Get(_ context.Context, id string) (*PushApproval, error) {
	if id == "" {
		return nil, ErrPushApprovalNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[id]
	if !ok {
		return nil, ErrPushApprovalNotFound
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(m.entries, id)
		return nil, ErrPushApprovalNotFound
	}
	cp := *entry
	return &cp, nil
}

// SetStatus transitions an entry from Pending to either Approved or
// Denied. Refuses changes to already-resolved approvals (returns
// ErrPushApprovalResolved). Missing entries surface as
// ErrPushApprovalNotFound. Same-status idempotent (Pending →
// Pending is a no-op).
func (m *MemoryPushApprovalStore) SetStatus(_ context.Context, id string, status PushApprovalStatus) error {
	if id == "" {
		return ErrPushApprovalNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[id]
	if !ok {
		return ErrPushApprovalNotFound
	}
	if entry.Status == status {
		return nil
	}
	if entry.Status != PushApprovalPending {
		return ErrPushApprovalResolved
	}
	entry.Status = status
	return nil
}

// Delete drops the entry. Idempotent (missing id → nil, not error)
// so cron cleanup loops can call it without error noise.
func (m *MemoryPushApprovalStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, id)
	return nil
}

// newPushApprovalID mints a 32-byte crypto/rand identifier — same
// shape MFA challenge IDs use, so the audit trail looks uniform.
// Kept private to defaultimpl: the equivalent helper in the root
// sso package would import-cycle here.
func newPushApprovalID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Interface guards.
var (
	_ spi.MFAProvider   = (*PushMFAProvider)(nil)
	_ spi.MFABeginner   = (*PushMFAProvider)(nil)
	_ PushApprovalStore = (*MemoryPushApprovalStore)(nil)
	_ PushTransport     = PushTransportFunc(nil)
)
