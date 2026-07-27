package audit

import (
	"context"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// Recorder is the entry point used by handlers / SDKs. It buffers nothing,
// it just adapts a Sink with a few conveniences:
//   - timestamp defaulting
//   - error redirection through ErrorHandler instead of returning
//   - nil-safe Record (so handlers can call it without conditional guards)
//   - optional server-version stamping for deployment-identity in every event
type Recorder struct {
	sink          Sink
	onError       ErrorHandler
	now           func() time.Time
	chain         *chainer
	redactor      Redactor
	serverVersion string
	// configChangeHook, when set via SetConfigChangeHook, runs on every
	// subsequent Record call AFTER redaction + hash-chain stamping (so it
	// observes the same event a Sink would). nil (the default) costs one
	// pointer nil-check per Record.
	configChangeHook func(context.Context, *Event)
}

type Option func(*Recorder)

// WithErrorHandler routes Sink.Record failures to fn instead of swallowing them.
func WithErrorHandler(fn ErrorHandler) Option {
	return func(r *Recorder) { r.onError = fn }
}

// WithClock overrides the timestamp source. Useful for tests.
func WithClock(now func() time.Time) Option {
	return func(r *Recorder) { r.now = now }
}

// WithHashChain enables tamper-evident hash chaining over recorded
// events. Each event's [Event.PrevHash] and [Event.Hash] fields are
// stamped before the sink sees it, so a tampered event breaks the
// chain at every subsequent event's recomputed hash.
//
// Verify offline with [VerifyChain] against a slice of events read
// from the sink (in chain order, oldest first — MemorySink returns
// newest-first by default).
//
// Cross-restart continuity: when the configured sink implements
// [ChainTip] (the SQLite sink does), the chain RESUMES from the last
// persisted event's Hash on construction, so the first event a fresh
// process records carries PrevHash == the last pre-restart Hash —
// VerifyChain sees one unbroken chain across the restart seam rather
// than a spurious second genesis. An empty store (or a memory-only
// sink that can't resume) seeds genesis. A tip-read error is
// best-effort: it seeds genesis and continues so a degraded sink
// never blocks recording — the only visible effect is a single
// chain break at this restart, identical to the pre-resume behavior.
func WithHashChain() Option {
	return func(r *Recorder) {
		r.chain = &chainer{}
		// Resume from durable storage before any event is stamped.
		// Options run after r.sink is set in New, so the sink (and its
		// optional ChainTip extension) is already in place here.
		if tip, ok := r.sink.(ChainTip); ok {
			if last, err := tip.LastHash(context.Background()); err == nil {
				r.chain.seed(last)
			}
		}
	}
}

// WithServerVersion sets the server version string that is stamped onto
// every recorded event's ServerVersion field. This lets operators
// correlate audit trails to specific binary versions during rolling
// deployments. Pass the result of [buildinfo.Resolve] or a similar
// version resolution. An empty string is a no-op (no stamping).
func WithServerVersion(version string) Option {
	return func(r *Recorder) {
		if version != "" {
			r.serverVersion = version
		}
	}
}

func New(sink Sink, opts ...Option) *Recorder {
	r := &Recorder{sink: sink, now: time.Now}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Sink returns the underlying sink. Used by query endpoints.
func (r *Recorder) Sink() Sink { return r.sink }

// SetConfigChangeHook wires fn to run on every subsequent Record call. Like
// AddSink, this mutates shared state — call it during wiring, before the
// Recorder is shared with request handlers. A nil fn disables the hook.
//
// This is the "narrowest existing seam" AGENTS.md's config-audit
// change-capture requirement asks for: every admin mutation (gRPC's
// recordAdmin helper AND the REST admin handlers) already funnels through
// Record with the actor stamped from the admin auth context, so hooking
// here — rather than at each individual admin_*.go call site — captures
// every admin event with zero changes to any of them. interfaces/sso wires
// this to append a platform/configaudit.Store entry for the client/tenant/
// policy event types (see Server.recordConfigHistoryFromAudit); it stays a
// plain func here so platform/audit has no dependency on configaudit.
func (r *Recorder) SetConfigChangeHook(fn func(context.Context, *Event)) {
	if r == nil {
		return
	}
	r.configChangeHook = fn
}

// AddSink fans every recorded event out to extra IN ADDITION to the
// existing sink, by wrapping the current sink in a MultiSink. The
// original sink stays first, so reads (Get/Query) keep being served by
// it; extra is a write-side tap (e.g. a CAEP Transmitter) whose Record
// runs after the primary's. Redaction + hash-chaining still happen once,
// before either sink sees the event (they run in Record ahead of the
// sink call), so the tap observes the SAME redacted, chained event the
// primary stored.
//
// Not safe for concurrent use with Record — call it during wiring,
// before the Recorder is shared with request handlers. No-op on a nil
// Recorder or nil extra.
func (r *Recorder) AddSink(extra Sink) {
	if r == nil || extra == nil {
		return
	}
	r.sink = NewMultiSink(r.sink, extra)
}

// Record persists e. Safe to call on a nil Recorder (no-op) so handlers can
// always invoke it without guard. Timestamp is filled in if zero. When the
// Recorder was constructed with [WithHashChain], the event's PrevHash + Hash
// fields are stamped before the sink sees it. When a server version was
// configured via [WithServerVersion], it is stamped onto every event.
func (r *Recorder) Record(ctx context.Context, e *Event) {
	if r == nil || r.sink == nil || e == nil {
		return
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = r.now()
	}
	// Server-version identity: stamp the deployment version so audit
	// consumers can correlate events with the binary that produced them
	// even across a rolling deployment. Stamped before redaction and
	// hashing so the version is part of the tamper-evident chain.
	if r.serverVersion != "" {
		e.ServerVersion = r.serverVersion
	}
	// Break-glass request-path attribution: when the action was performed under a
	// break-glass impersonation bearer, stamp the acting admin + grant id alongside
	// the target subject (Event.ActorID) so the SOC 2 evidence chain rides EVERY
	// event, not just the mint. Stamped before redaction + hashing so it's part of
	// the tamper-evident chain. No-op (byte-identical) for an ordinary request.
	if bg, ok := core.BreakGlassActorFromContext(ctx); ok {
		SetMeta(e, core.ClaimBreakGlass, "true")
		SetMeta(e, core.MetaBreakGlassAdminID, bg.AdminID)
		SetMeta(e, core.ClaimBreakGlassAdminSessionID, bg.AdminSessionID)
	}
	// Redaction runs BEFORE the hash chainer so the chain validates
	// over the redacted form. A downstream verifier shouldn't need
	// access to the pre-redaction values to check chain integrity.
	if r.redactor != nil {
		r.redactor.Redact(e)
	}
	if r.chain != nil {
		r.chain.stamp(e)
	}
	if err := r.sink.Record(ctx, e); err != nil && r.onError != nil {
		r.onError(err)
	}
	if r.configChangeHook != nil {
		r.configChangeHook(ctx, e)
	}
}
