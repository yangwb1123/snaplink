package authenticators

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/spi"
)

// ErrCodeInvalid is returned when a verification code does not match or has expired.
var ErrCodeInvalid = errors.New("authenticators: code invalid or expired")

var (
	ErrCodeDeliveryQueueFull   = errors.New("authenticators: code delivery queue full")
	ErrCodeDeliveryQueueClosed = errors.New("authenticators: code delivery queue closed")
)

// DefaultCodeResendCooldown is the minimum interval between OTP sends to the
// same target. Prevents amplification attacks via repeated /send-code calls.
const DefaultCodeResendCooldown = 60 * time.Second

// DefaultCodeMaxAttempts is the number of failed verification attempts allowed
// for one issued code. The final failed attempt invalidates that code.
const DefaultCodeMaxAttempts = 5

const (
	DefaultCodeIdentitySendLimit = 20
	DefaultCodeTenantSendLimit   = 1000
	DefaultCodeSendQuotaWindow   = 24 * time.Hour
	DefaultCodeDeliveryQueueSize = 256
	DefaultCodeDeliveryWorkers   = 2
	DefaultCodeDeliveryAttempts  = 3
	DefaultCodeDeliveryTimeout   = 10 * time.Second
	DefaultCodeDeliveryBackoff   = 200 * time.Millisecond
	MaxCodeDeliveryQueueSize     = 10000
	MaxCodeDeliveryWorkers       = 64
	MaxCodeDeliveryAttempts      = 10
	MaxCodeDeliveryTimeout       = 2 * time.Minute
	MaxCodeDeliveryBackoff       = 30 * time.Second
)

// AsyncCodeSenderConfig bounds the optional in-memory delivery queue. Secrets
// remain memory-only and expire through the CodeStore even if the process dies.
type AsyncCodeSenderConfig struct {
	QueueSize      int
	Workers        int
	Attempts       int
	AttemptTimeout time.Duration
	RetryBackoff   time.Duration
}

// DeferredCodeSender lets authenticators attach compensating invalidation to
// an accepted asynchronous delivery without widening EmailSender/SMSSender.
type DeferredCodeSender interface {
	SendDeferred(context.Context, string, string, func(context.Context)) error
}

type codeDeliveryJob struct {
	ctx       context.Context
	target    string
	payload   string
	onFailure func(context.Context)
}

// AsyncCodeSender is a bounded worker queue shared by email and SMS adapters.
// It retries delivery off the request path and never logs target or payload.
type AsyncCodeSender struct {
	send      func(context.Context, string, string) error
	observe   func(context.Context, string, error)
	cfg       AsyncCodeSenderConfig
	jobs      chan codeDeliveryJob
	workerCtx context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
	jobsWG    sync.WaitGroup
	workersWG sync.WaitGroup
	drained   chan struct{}
}

// NewAsyncCodeSender starts the configured worker pool. observe receives only
// the bounded outcomes "delivered"/"failed" and the transport error.
func NewAsyncCodeSender(send func(context.Context, string, string) error, cfg AsyncCodeSenderConfig, observe func(context.Context, string, error)) *AsyncCodeSender {
	cfg = normalizeAsyncCodeSenderConfig(cfg)
	workerCtx, cancel := context.WithCancel(context.Background())
	q := &AsyncCodeSender{
		send: send, observe: observe, cfg: cfg, jobs: make(chan codeDeliveryJob, cfg.QueueSize),
		workerCtx: workerCtx, cancel: cancel, drained: make(chan struct{}),
	}
	q.workersWG.Add(cfg.Workers)
	for range cfg.Workers {
		go q.runWorker()
	}
	return q
}

func normalizeAsyncCodeSenderConfig(cfg AsyncCodeSenderConfig) AsyncCodeSenderConfig {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultCodeDeliveryQueueSize
	} else if cfg.QueueSize > MaxCodeDeliveryQueueSize {
		cfg.QueueSize = MaxCodeDeliveryQueueSize
	}
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultCodeDeliveryWorkers
	} else if cfg.Workers > MaxCodeDeliveryWorkers {
		cfg.Workers = MaxCodeDeliveryWorkers
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = DefaultCodeDeliveryAttempts
	} else if cfg.Attempts > MaxCodeDeliveryAttempts {
		cfg.Attempts = MaxCodeDeliveryAttempts
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = DefaultCodeDeliveryTimeout
	} else if cfg.AttemptTimeout > MaxCodeDeliveryTimeout {
		cfg.AttemptTimeout = MaxCodeDeliveryTimeout
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = DefaultCodeDeliveryBackoff
	} else if cfg.RetryBackoff > MaxCodeDeliveryBackoff {
		cfg.RetryBackoff = MaxCodeDeliveryBackoff
	}
	return cfg
}

// Send implements both EmailSender and SMSSender with no failure callback.
func (q *AsyncCodeSender) Send(ctx context.Context, target, payload string) error {
	return q.SendDeferred(ctx, target, payload, nil)
}

// SendDeferred accepts a job without waiting on the external provider. A full
// or closed queue fails synchronously so the authenticator can roll back.
func (q *AsyncCodeSender) SendDeferred(ctx context.Context, target, payload string, onFailure func(context.Context)) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrCodeDeliveryQueueClosed
	}
	job := codeDeliveryJob{ctx: context.WithoutCancel(ctx), target: target, payload: payload, onFailure: onFailure}
	q.jobsWG.Add(1)
	select {
	case q.jobs <- job:
		return nil
	default:
		q.jobsWG.Done()
		return ErrCodeDeliveryQueueFull
	}
}

func (q *AsyncCodeSender) runWorker() {
	defer q.workersWG.Done()
	for {
		select {
		case job := <-q.jobs:
			q.deliver(job)
			q.jobsWG.Done()
		case <-q.workerCtx.Done():
			return
		}
	}
}

func (q *AsyncCodeSender) deliver(job codeDeliveryJob) {
	var err error
	for attempt := 0; attempt < q.cfg.Attempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(job.ctx, q.cfg.AttemptTimeout)
		stop := context.AfterFunc(q.workerCtx, cancel)
		err = q.send(attemptCtx, job.target, job.payload)
		stop()
		cancel()
		if err == nil {
			q.observeOutcome(job.ctx, "delivered", nil)
			return
		}
		if attempt+1 < q.cfg.Attempts && !q.waitRetry(attempt) {
			break
		}
	}
	if job.onFailure != nil {
		cleanupCtx, cancel := context.WithTimeout(job.ctx, q.cfg.AttemptTimeout)
		job.onFailure(cleanupCtx)
		cancel()
	}
	q.observeOutcome(job.ctx, "failed", err)
}

func (q *AsyncCodeSender) waitRetry(attempt int) bool {
	delay := q.cfg.RetryBackoff * time.Duration(1<<attempt)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-q.workerCtx.Done():
		return false
	}
}

func (q *AsyncCodeSender) observeOutcome(ctx context.Context, outcome string, err error) {
	if q.observe != nil {
		q.observe(ctx, outcome, err)
	}
}

// Close stops accepting work and drains accepted jobs within ctx's deadline.
func (q *AsyncCodeSender) Close(ctx context.Context) error {
	q.closeOnce.Do(func() {
		q.mu.Lock()
		q.closed = true
		q.mu.Unlock()
		go func() {
			q.jobsWG.Wait()
			q.cancel()
			q.workersWG.Wait()
			close(q.drained)
		}()
	})
	select {
	case <-q.drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type codeTransport interface {
	Send(context.Context, string, string) error
}

func dispatchCodeDelivery(ctx context.Context, sender codeTransport, target, payload string, onFailure func(context.Context)) error {
	var err error
	if deferred, ok := sender.(DeferredCodeSender); ok {
		err = deferred.SendDeferred(ctx, target, payload, onFailure)
	} else {
		err = sender.Send(ctx, target, payload)
	}
	if err != nil && onFailure != nil {
		onFailure(ctx)
	}
	return err
}

// CodeSendQuota configures fixed-window outbound code budgets. A zero limit
// disables that dimension. Identity is scoped inside the resolved tenant.
type CodeSendQuota struct {
	IdentityLimit int
	TenantLimit   int
	Window        time.Duration
}

// DefaultCodeSendQuota returns the stock cost-abuse policy.
func DefaultCodeSendQuota() CodeSendQuota {
	return CodeSendQuota{
		IdentityLimit: DefaultCodeIdentitySendLimit,
		TenantLimit:   DefaultCodeTenantSendLimit,
		Window:        DefaultCodeSendQuotaWindow,
	}
}

// CodeStore stores short-lived one-time verification codes (SMS / email / magic link).
// Save persists a (key, code) pair with a TTL. Verify performs a constant-time
// comparison and consumes the code on success.
type CodeStore interface {
	Save(ctx context.Context, key, code string, ttl time.Duration) error
	Verify(ctx context.Context, key, code string) error
}

// CodeInvalidator is an optional CodeStore capability used to compensate a
// failed delivery. Implementations delete only when code is still the current
// value so a delayed sender failure cannot invalidate a newer issuance.
type CodeInvalidator interface {
	Invalidate(ctx context.Context, key, code string) error
}

// MemoryCodeStore is a process-local CodeStore. Use Redis or a database in production.
type MemoryCodeStore struct {
	mu           sync.Mutex
	entries      map[string]codeEntry
	quotaBuckets map[string]codeQuotaBucket
	cooldown     time.Duration
	maxTries     int
	quota        CodeSendQuota
}

type codeEntry struct {
	code      string
	expiresAt time.Time
	savedAt   time.Time
	failed    int
	quotaKey  string
	reserved  bool
}

type codeQuotaBucket struct {
	expiresAt  time.Time
	total      int
	identities map[string]int
}

func NewMemoryCodeStore() *MemoryCodeStore {
	return &MemoryCodeStore{
		entries:      make(map[string]codeEntry),
		quotaBuckets: make(map[string]codeQuotaBucket),
		cooldown:     DefaultCodeResendCooldown,
		maxTries:     DefaultCodeMaxAttempts,
		quota:        DefaultCodeSendQuota(),
	}
}

// NewMemoryCodeStoreWithCooldown creates a MemoryCodeStore with a custom cooldown.
// Pass 0 to disable cooldown enforcement (for tests and single-use scenarios).
func NewMemoryCodeStoreWithCooldown(cooldown time.Duration) *MemoryCodeStore {
	return NewMemoryCodeStoreWithQuota(cooldown, DefaultCodeSendQuota())
}

// NewMemoryCodeStoreWithQuota creates a store with explicit cooldown and
// delivery budgets. Zero limits disable their respective quota dimension.
func NewMemoryCodeStoreWithQuota(cooldown time.Duration, quota CodeSendQuota) *MemoryCodeStore {
	return &MemoryCodeStore{
		entries:      make(map[string]codeEntry),
		quotaBuckets: make(map[string]codeQuotaBucket),
		cooldown:     cooldown,
		maxTries:     DefaultCodeMaxAttempts,
		quota:        normalizeCodeSendQuota(quota),
	}
}

func (m *MemoryCodeStore) Save(ctx context.Context, key, code string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if m.cooldown > 0 {
		if e, ok := m.entries[key]; ok && now.Sub(e.savedAt) < m.cooldown {
			return spi.ErrCodeCooldownActive
		}
	}
	quotaKey := codeQuotaTenant(ctx)
	reserved, err := m.reserveQuota(now, quotaKey, key)
	if err != nil {
		return err
	}
	m.entries[key] = codeEntry{
		code: code, expiresAt: now.Add(ttl), savedAt: now,
		quotaKey: quotaKey, reserved: reserved,
	}
	return nil
}

func normalizeCodeSendQuota(quota CodeSendQuota) CodeSendQuota {
	if quota.IdentityLimit < 0 {
		quota.IdentityLimit = 0
	}
	if quota.TenantLimit < 0 {
		quota.TenantLimit = 0
	}
	if quota.Window <= 0 {
		quota.Window = DefaultCodeSendQuotaWindow
	}
	return quota
}

func codeQuotaTenant(ctx context.Context) string {
	if tenantID := spi.CodeSendTenant(ctx); tenantID != "" {
		return tenantID
	}
	return "_public"
}

func (m *MemoryCodeStore) reserveQuota(now time.Time, tenantID, identity string) (bool, error) {
	if m.quota.IdentityLimit == 0 && m.quota.TenantLimit == 0 {
		return false, nil
	}
	bucket, ok := m.quotaBuckets[tenantID]
	if !ok || !now.Before(bucket.expiresAt) {
		bucket = codeQuotaBucket{expiresAt: now.Add(m.quota.Window), identities: make(map[string]int)}
	}
	if (m.quota.IdentityLimit > 0 && bucket.identities[identity] >= m.quota.IdentityLimit) ||
		(m.quota.TenantLimit > 0 && bucket.total >= m.quota.TenantLimit) {
		return false, spi.ErrCodeSendQuotaExceeded
	}
	bucket.identities[identity]++
	bucket.total++
	m.quotaBuckets[tenantID] = bucket
	return true, nil
}

func (m *MemoryCodeStore) releaseQuota(tenantID, identity string) {
	bucket, ok := m.quotaBuckets[tenantID]
	if !ok {
		return
	}
	if bucket.identities[identity] > 0 {
		bucket.identities[identity]--
		bucket.total--
	}
	m.quotaBuckets[tenantID] = bucket
}

func (m *MemoryCodeStore) Verify(_ context.Context, key, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok || time.Since(e.expiresAt) > 0 {
		delete(m.entries, key)
		return ErrCodeInvalid
	}
	if subtle.ConstantTimeCompare([]byte(e.code), []byte(code)) != 1 {
		e.failed++
		if m.maxTries > 0 && e.failed >= m.maxTries {
			delete(m.entries, key)
		} else {
			m.entries[key] = e
		}
		return ErrCodeInvalid
	}
	delete(m.entries, key)
	return nil
}

// Invalidate removes an undelivered code and its embedded resend cooldown, but
// only if a newer SendCode call has not replaced it.
func (m *MemoryCodeStore) Invalidate(_ context.Context, key, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if ok && subtle.ConstantTimeCompare([]byte(e.code), []byte(code)) == 1 {
		delete(m.entries, key)
		if e.reserved {
			m.releaseQuota(e.quotaKey, key)
		}
	}
	return nil
}

func invalidateUndeliveredCode(ctx context.Context, store CodeStore, key, code string) {
	if invalidator, ok := store.(CodeInvalidator); ok {
		_ = invalidator.Invalidate(ctx, key, code)
	}
}

// GenerateNumericCode returns a cryptographically random decimal string of length n.
func GenerateNumericCode(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("authenticators: code length must be positive")
	}
	out := make([]byte, n)
	max := big.NewInt(int64(len(numericDigits)))
	for i := range n {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = numericDigits[idx.Int64()]
	}
	return string(out), nil
}

// GenerateOpaqueToken returns a cryptographically random, URL-safe opaque
// token with nBytes of raw entropy (crypto/rand, base64.RawURLEncoding —
// no padding, alphabet safe unescaped in a URL path or query value). This is
// the SAME construction TempTokenAuthenticator.Issue already uses for
// single-use bearer tokens (magic links / password-reset confirmations /
// device-transfer codes per its doc comment); MagicLinkAuthenticator.SendCode
// calls this rather than re-deriving its own byte-generation scheme.
func GenerateOpaqueToken(nBytes int) (string, error) {
	if nBytes <= 0 {
		return "", fmt.Errorf("authenticators: token byte length must be positive")
	}
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
