// Package notification routes immutable audit events into user-facing,
// preference-aware delivery channels without blocking the audit path.
package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/sse"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

const (
	defaultCooldown       = 5 * time.Minute
	defaultQueue          = 256
	defaultWorkers        = 2
	defaultSessionWarning = 30 * time.Minute
	defaultSessionScan    = time.Minute
)

// DeliveryObserver receives bounded channel/outcome values.
type DeliveryObserver func(channel, outcome string)

type Option func(*Router)

func WithCooldown(value time.Duration) Option {
	return func(r *Router) {
		if value >= 0 {
			r.cooldown = value
		}
	}
}
func WithQueueSize(value int) Option {
	return func(r *Router) {
		if value > 0 {
			r.queue = make(chan *audit.Event, value)
		}
	}
}
func WithWorkers(value int) Option {
	return func(r *Router) {
		if value > 0 {
			r.workers = value
		}
	}
}
func WithObserver(fn DeliveryObserver) Option { return func(r *Router) { r.observer = fn } }
func WithClock(now func() time.Time) Option {
	return func(r *Router) {
		if now != nil {
			r.now = now
		}
	}
}
func WithBroker(b *sse.Broker) Option { return func(r *Router) { r.broker = b } }
func WithSessionExpiry(lister core.SessionManager, warning, scan time.Duration) Option {
	return func(r *Router) {
		r.sessions = lister
		if warning > 0 {
			r.sessionWarning = warning
		}
		if scan > 0 {
			r.sessionScan = scan
		}
	}
}

// Router is an audit.Sink write tap. Query/Get intentionally return no data;
// MultiSink keeps reads on the primary audit sink.
type Router struct {
	mapping        map[audit.EventType]core.NotificationType
	prefs          core.NotificationPreferenceStore
	senders        map[core.NotificationChannel]core.NotificationSender
	log            spi.Logger
	queue          chan *audit.Event
	workers        int
	cooldown       time.Duration
	now            func() time.Time
	observer       DeliveryObserver
	broker         *sse.Broker
	sessions       core.SessionManager
	users          core.UserProvider
	sessionWarning time.Duration
	sessionScan    time.Duration
	mu             sync.Mutex
	recent         map[string]time.Time
	start          sync.Once
	done           chan struct{}
	cancel         context.CancelFunc
}

func NewRouter(mapping map[audit.EventType]core.NotificationType, prefs core.NotificationPreferenceStore,
	senders map[core.NotificationChannel]core.NotificationSender, log spi.Logger, opts ...Option) *Router {
	if len(mapping) == 0 {
		mapping = DefaultMappings()
	}
	if log == nil {
		log = spi.NopLogger{}
	}
	r := &Router{mapping: cloneMappings(mapping), prefs: prefs, senders: senders, log: log,
		queue: make(chan *audit.Event, defaultQueue), workers: defaultWorkers, cooldown: defaultCooldown,
		now: time.Now, recent: map[string]time.Time{}, sessionWarning: defaultSessionWarning,
		sessionScan: defaultSessionScan}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// DefaultMappings maps security-relevant audit events to stable inbox types.
func DefaultMappings() map[audit.EventType]core.NotificationType {
	return map[audit.EventType]core.NotificationType{
		audit.EventNewDeviceLogin:            core.NotificationNewDeviceLogin,
		audit.EventDeviceTrustRevoked:        core.NotificationMFARemoved,
		audit.EventMFARemoved:                core.NotificationMFARemoved,
		audit.EventConsentGranted:            core.NotificationConsentGranted,
		audit.EventConsentRevoked:            core.NotificationConsentGranted,
		audit.EventPasswordCompromised:       core.NotificationPasswordLeaked,
		audit.EventPasswordChanged:           core.NotificationSecurityEvent,
		audit.EventPasswordResetCompleted:    core.NotificationSecurityEvent,
		audit.EventPasswordExpiring:          core.NotificationPasswordExpiring,
		audit.EventAccountLocked:             core.NotificationAccountLocked,
		audit.EventAnomalyDetected:           core.NotificationSecurityEvent,
		audit.EventRefreshTokenReuse:         core.NotificationSecurityEvent,
		audit.EventAdminRoleAssigned:         core.NotificationSecurityEvent,
		audit.EventAdminRoleUnassigned:       core.NotificationSecurityEvent,
		audit.EventAdminConsentRevoked:       core.NotificationConsentGranted,
		audit.EventAdminMFAFactorRemoved:     core.NotificationMFARemoved,
		audit.EventAdminRecoveryCodesReset:   core.NotificationSecurityEvent,
		audit.EventAdminPasswordReset:        core.NotificationSecurityEvent,
		audit.EventAdminUserEmailChanged:     core.NotificationSecurityEvent,
		audit.EventAdminDeviceSecretsRevoked: core.NotificationSecurityEvent,
		audit.EventAdminRefreshTokensRevoked: core.NotificationSecurityEvent,
	}
}

// Start launches bounded workers and closes done once ctx is cancelled and the
// already-dequeued work finishes. Calls after the first return the same channel.
func (r *Router) Start(ctx context.Context) <-chan struct{} {
	r.start.Do(func() {
		r.done = make(chan struct{})
		ctx, r.cancel = context.WithCancel(ctx)
		var wg sync.WaitGroup
		for i := 0; i < r.workers; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); r.run(ctx) }()
		}
		if r.sessions != nil {
			wg.Add(1)
			go func() { defer wg.Done(); r.runSessionSweep(ctx) }()
		}
		go func() { wg.Wait(); close(r.done) }()
	})
	return r.done
}

// Close stops workers and waits for their bounded in-flight deliveries.
func (r *Router) Close(ctx context.Context) error {
	if r == nil || r.cancel == nil {
		return nil
	}
	r.cancel()
	defer func() {
		if r.broker != nil {
			r.broker.Close()
		}
	}()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Router) Broker() *sse.Broker {
	if r == nil {
		return nil
	}
	return r.broker
}

func (r *Router) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-r.queue:
			r.route(ctx, event)
		}
	}
}

func (r *Router) Record(_ context.Context, event *audit.Event) error {
	if event == nil {
		return nil
	}
	copyEvent := *event
	if event.Metadata != nil {
		copyEvent.Metadata = make(map[string]string, len(event.Metadata))
		for key, value := range event.Metadata {
			copyEvent.Metadata[key] = value
		}
	}
	select {
	case r.queue <- &copyEvent:
	default:
		r.observe("queue", "dropped")
	}
	return nil
}

func (r *Router) Query(context.Context, audit.Query) ([]*audit.Event, error) { return nil, nil }
func (r *Router) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrEventNotFound
}

func (r *Router) route(ctx context.Context, event *audit.Event) {
	typ, ok := r.mapping[event.Type]
	if !ok {
		return
	}
	r.routeNotification(ctx, typ, event)
}

func (r *Router) routeNotification(ctx context.Context, typ core.NotificationType, event *audit.Event) {
	subjectID := r.eventSubject(ctx, event)
	if subjectID == "" || r.suppressed(subjectID, typ) {
		return
	}
	title, body, severity := presentation(typ, event)
	for channel, sender := range r.senders {
		if sender == nil || !r.enabled(ctx, subjectID, typ, channel) {
			continue
		}
		n := &core.NotificationEvent{SubjectID: subjectID, TenantID: event.TenantID, Type: typ,
			Title: title, Body: body, Severity: severity, Channel: channel, CreatedAt: r.now().UTC()}
		r.deliver(ctx, channel, sender, n)
	}
}

func (r *Router) runSessionSweep(ctx context.Context) {
	r.sweepSessions(ctx)
	ticker := time.NewTicker(r.sessionScan)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sweepSessions(ctx)
		}
	}
}

func (r *Router) sweepSessions(ctx context.Context) {
	sessions, err := r.sessions.ListAll(ctx)
	if err != nil {
		r.log.Error("notification session-expiry scan failed", "error", err)
		return
	}
	now := r.now()
	for _, session := range sessions {
		if session == nil {
			continue
		}
		remaining := session.ExpiresAt.Sub(now)
		if remaining <= 0 || remaining > r.sessionWarning {
			continue
		}
		r.routeNotification(ctx, core.NotificationSessionExpiring,
			&audit.Event{ActorID: session.UserID, TenantID: session.TenantID})
	}
}

func (r *Router) deliver(ctx context.Context, channel core.NotificationChannel, sender core.NotificationSender, event *core.NotificationEvent) {
	attempts := 1
	if channel == core.NotificationChannelEmail {
		attempts = 3
	}
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if err = sender.SendNotification(ctx, event); err == nil {
			r.observe(string(channel), "success")
			if channel == core.NotificationChannelInApp {
				r.publish(event)
			}
			return
		}
		if attempt+1 == attempts {
			break
		}
		select {
		case <-ctx.Done():
			attempt = attempts
		case <-time.After(time.Duration(attempt+1) * 25 * time.Millisecond):
		}
	}
	r.log.Error("notification delivery failed", "channel", channel, "type", event.Type, "error", err)
	r.observe(string(channel), "failed")
}

func (r *Router) publish(event *core.NotificationEvent) {
	if r.broker == nil {
		return
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	r.broker.Publish(sse.Event{Type: "notification", TenantID: event.TenantID, SubjectID: event.SubjectID, Data: data})
}

func (r *Router) enabled(ctx context.Context, subjectID string, typ core.NotificationType, channel core.NotificationChannel) bool {
	if r.prefs == nil {
		return true
	}
	values, err := r.prefs.ListBySubject(ctx, subjectID)
	if err != nil {
		return true
	}
	for _, value := range values {
		if value.Type == typ && value.Channel == channel {
			return value.Enabled
		}
	}
	return true
}

func (r *Router) suppressed(subjectID string, typ core.NotificationType) bool {
	if r.cooldown == 0 {
		return false
	}
	now, key := r.now(), subjectID+"\x00"+string(typ)
	r.mu.Lock()
	defer r.mu.Unlock()
	if until := r.recent[key]; until.After(now) {
		return true
	}
	r.recent[key] = now.Add(r.cooldown)
	return false
}

func (r *Router) observe(channel, outcome string) {
	if r.observer != nil {
		r.observer(channel, outcome)
	}
}

func presentation(typ core.NotificationType, event *audit.Event) (string, string, core.NotificationSeverity) {
	if title, body, severity, ok := auditEventPresentation(event); ok {
		return title, body, severity
	}
	switch typ {
	case core.NotificationNewDeviceLogin:
		return "New device sign-in", "Your account was used to sign in from a new device.", core.NotificationWarning
	case core.NotificationMFARemoved:
		return "Security factor removed", "A trusted device or multi-factor method was removed.", core.NotificationWarning
	case core.NotificationConsentGranted:
		return "Application access granted", fmt.Sprintf("Access was granted to application %s.", event.ClientID), core.NotificationInfo
	case core.NotificationPasswordLeaked:
		return "Compromised password detected", "Change your password immediately and review active sessions.", core.NotificationCritical
	case core.NotificationPasswordExpiring:
		return "Password expiring soon", "Change your password before it expires to avoid losing access.", core.NotificationWarning
	case core.NotificationAccountLocked:
		return "Account locked", "Your account was locked after repeated authentication failures.", core.NotificationCritical
	case core.NotificationSessionExpiring:
		return "Session expiring soon", "One of your active sessions will expire soon. Sign in again if you still need access.", core.NotificationWarning
	default:
		return "Security activity detected", "Review recent security activity and active sessions.", core.NotificationWarning
	}
}

func cloneMappings(in map[audit.EventType]core.NotificationType) map[audit.EventType]core.NotificationType {
	out := make(map[audit.EventType]core.NotificationType, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

var _ audit.Sink = (*Router)(nil)
