package caep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

// Client metadata keys (anti-exfil: the receiver address is read ONLY
// from the affected client's REGISTERED metadata, never from request
// input). Stored in core.Client.Attributes.
const (
	// AttrReceiverEndpoint is the HTTPS URL the SET is POSTed to. Set on a
	// client to opt that RP into receiving Shared Signals. Validated at
	// client create/update time (must parse + be https). Absent ⇒ the RP
	// receives no SETs.
	AttrReceiverEndpoint = "caep_receiver_endpoint"

	// AttrReceiverAuth is the literal Authorization header value the SET
	// POST carries (e.g. "Bearer <token>"). The RP authenticates the
	// transmitter with it. Absent ⇒ no Authorization header (only safe
	// when the receiver is on a trusted network or uses mTLS at the edge).
	AttrReceiverAuth = "caep_receiver_auth"
)

// Audit metadata keys the broadcaster reads / writes.
const (
	// MetaAffectedClient — set by an emitter on an admin_token_revoked
	// audit event to name the AFFECTED RP (not the calling admin's
	// client). Without it that event does not broadcast (see mapAuditEvent).
	MetaAffectedClient = "caep_affected_client"

	// MetaSubject — optional subject override on an event whose ActorID is
	// not the affected end-user (e.g. admin events where ActorID is the
	// admin). When present it populates the SET sub_id.
	MetaSubject = "caep_subject"
)

// EventCAEPBroadcastFailed is the internal audit event recorded when a
// SET could not be delivered to a receiver. INTERNAL operator signal, not
// a wire error code — broadcasting is best-effort and fail-open (the
// revocation it announces already happened locally), so a delivery
// failure NEVER affects the triggering operation. Reason carries the
// receiver + failure detail; ClientID names the affected RP.
const EventCAEPBroadcastFailed audit.EventType = "caep_broadcast_failed"

// SET delivery outcome labels for the sso_caep_sets_total metric. Bounded
// cardinality by construction (three fixed values).
const (
	OutcomeSuccess = "success"
	OutcomeFailed  = "failed"
	OutcomeDropped = "dropped"
)

// DefaultReceiverTimeout caps a single SET POST. A slow/dead receiver
// must not pin a broadcast goroutine: past this bound the context is
// cancelled, the SET is dropped (metric + audit), and the goroutine
// returns. 10s is generous for a healthy receiver yet short enough to
// reclaim a goroutine promptly.
const DefaultReceiverTimeout = 10 * time.Second

// MetricFunc records one SET delivery outcome. Wired by cmd to the
// sso_caep_sets_total{outcome} Prometheus counter; nil ⇒ no metric.
// Matches the func-callback metric seam the anomaly + CIBA subsystems use
// (keeps caep free of a prometheus import).
type MetricFunc func(outcome string)

// Logger is the minimal logging surface the transmitter needs. Satisfied
// by spi.Logger; kept local so caep depends only on core + audit.
type Logger interface {
	Error(msg string, args ...any)
}

// Transmitter is the CAEP/SSF Shared Security Signals transmitter. It is
// an audit.Sink: composed into the audit pipeline (via WithCAEPTransmitter
// or directly in a MultiSink), it inspects every recorded event, maps the
// small mapped subset to an SSF SET, resolves the AFFECTED receiver(s)
// FRESH from the ClientStore, mints a per-receiver SET signed by the
// trusted JWKS key, and POSTs it ASYNC + best-effort. A dead receiver
// drops the SET (metric + failure audit) and never blocks the triggering
// operation.
//
// Read methods (Get/Query) are write-only stubs — a transmitter stores
// nothing; in a MultiSink the readable primary sink answers reads.
type Transmitter struct {
	signer       JWTSigner
	clients      core.ClientStore
	tenantScoped core.TenantScopedClientStore // optional; nil ⇒ tenant fan-out is a no-op
	issuer       string                       // SET `iss`; the AS issuer URL
	httpClient   *http.Client
	timeout      time.Duration
	recorder     *audit.Recorder // failure-audit sink; may be nil
	metric       MetricFunc
	logger       Logger
	setTTL       time.Duration

	// wg tracks in-flight async sends so Close can drain them on shutdown
	// rather than abandoning goroutines mid-POST.
	wg sync.WaitGroup
}

// Option configures a Transmitter at construction.
type Option func(*Transmitter)

// WithIssuer sets the SET `iss` claim — SHOULD equal the AS issuer URL so
// a receiver can pin the expected SET issuer to the same value it sees in
// its tokens. Defaults to empty (the RP relies on the signing key + aud).
func WithIssuer(iss string) Option { return func(t *Transmitter) { t.issuer = iss } }

// WithHTTPClient injects a custom *http.Client (proxies, custom roots,
// tracing). Its Timeout is honored alongside the per-send context bound.
func WithHTTPClient(c *http.Client) Option {
	return func(t *Transmitter) {
		if c != nil {
			t.httpClient = c
		}
	}
}

// WithReceiverTimeout overrides the per-receiver POST timeout
// (DefaultReceiverTimeout). Values <= 0 are ignored.
func WithReceiverTimeout(d time.Duration) Option {
	return func(t *Transmitter) {
		if d > 0 {
			t.timeout = d
		}
	}
}

// WithFailureRecorder wires the audit Recorder the transmitter writes
// caep_broadcast_failed events to. PASS A DIFFERENT recorder than the one
// this transmitter is composed into, or accept that failure events are
// re-inspected here (harmless: caep_broadcast_failed is unmapped, so it
// never re-broadcasts). nil ⇒ failures are logged only.
func WithFailureRecorder(r *audit.Recorder) Option {
	return func(t *Transmitter) { t.recorder = r }
}

// WithMetric wires the SET-delivery outcome counter.
func WithMetric(fn MetricFunc) Option { return func(t *Transmitter) { t.metric = fn } }

// WithLogger wires error logging. nil ⇒ silent.
func WithLogger(l Logger) Option { return func(t *Transmitter) { t.logger = l } }

// WithSETTTL overrides the SET lifetime (DefaultSETTTL). Values <= 0 are
// ignored.
func WithSETTTL(d time.Duration) Option {
	return func(t *Transmitter) {
		if d > 0 {
			t.setTTL = d
		}
	}
}

// NewTransmitter builds a Transmitter. signer (the generic-JWT signer,
// typically the same issuer that mints access tokens) and clients (the
// ClientStore receivers are resolved FRESH from at send time) are
// required; a nil either yields a transmitter whose Record is an inert
// no-op (so a half-wired config degrades safely rather than panicking).
//
// If clients also implements core.TenantScopedClientStore it is used for
// tenant-scoped fan-out; otherwise tenant-wide events resolve to no
// receivers (they are not broadcast to all clients — that would leak).
func NewTransmitter(signer JWTSigner, clients core.ClientStore, opts ...Option) *Transmitter {
	t := &Transmitter{
		signer:  signer,
		clients: clients,
		// Redirect-follow is disabled: a registered receiver that 302s to an
		// internal IP would otherwise bypass the https-only URL validation done
		// at client create/update time (the same SSRF pivot that the federation
		// fetcher and SAML SLO fan-out explicitly close). We treat the stored
		// endpoint as authoritative and never follow redirects.
		httpClient: &http.Client{
			Timeout:       DefaultReceiverTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		timeout: DefaultReceiverTimeout,
		setTTL:  DefaultSETTTL,
	}
	if ts, ok := clients.(core.TenantScopedClientStore); ok {
		t.tenantScoped = ts
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// Record implements audit.Sink. It NEVER blocks the caller on network
// I/O: it maps the event (cheap), resolves affected clients (a local
// ClientStore read), then dispatches each SET POST to its own supervised
// goroutine. Any error here (mapping miss, no receivers) is silent — the
// transmitter is a fan-out tap, not the audit system of record. Returns
// nil unconditionally so it never disturbs a MultiSink's other sinks.
func (t *Transmitter) Record(ctx context.Context, e *audit.Event) error {
	if t == nil || t.signer == nil || t.clients == nil {
		return nil
	}
	mapped, ok := mapAuditEvent(e)
	if !ok {
		return nil
	}
	// Allow a subject override from metadata (admin events).
	if subj := metaValue(e, MetaSubject); subj != "" {
		mapped.subject = subj
	}

	// Resolve the AFFECTED receiver client(s) FRESH from the ClientStore.
	// No cache, no cluster bus: a stale cache could push to a since-removed
	// receiver, and a fresh read is cheap relative to the outbound POST.
	// This is the simplest correct design (decision: resolve fresh, no bus).
	clients := t.resolveClients(ctx, mapped)
	for _, c := range clients {
		endpoint := receiverEndpoint(c)
		if endpoint == "" {
			continue // RP not opted into Shared Signals.
		}
		auth := ""
		if c.Attributes != nil {
			auth = c.Attributes[AttrReceiverAuth]
		}
		req := buildSETRequest{
			Issuer:   t.issuer,
			Audience: c.ID,
			Subject:  mapped.subject,
			Events:   mapped.events,
		}
		t.wg.Add(1)
		go t.deliver(c.ID, endpoint, auth, req)
	}
	return nil
}

// resolveClients returns the affected receiver clients per the mapped
// event's scope. scopeClient resolves the single named client;
// scopeTenant fans out across the tenant's clients (and ONLY that
// tenant's — the cross-tenant-no-leak guarantee). A lookup failure
// returns no clients (fail-open: the revocation already happened).
func (t *Transmitter) resolveClients(ctx context.Context, m mappedEvent) []*core.Client {
	switch m.scope {
	case scopeClient:
		if m.affectedClientID == "" {
			return nil
		}
		c, err := t.clients.Get(ctx, m.affectedClientID)
		if err != nil || c == nil {
			return nil
		}
		return []*core.Client{c}
	case scopeTenant:
		if t.tenantScoped == nil || m.tenantID == "" {
			return nil
		}
		clients, err := t.tenantScoped.ListByTenant(ctx, m.tenantID)
		if err != nil {
			return nil
		}
		return clients
	default:
		return nil
	}
}

// deliver supervises a single SET mint + POST in its own goroutine,
// mirroring the CIBA-ping hardening (bounded context + recover + metric +
// failure audit). It runs OFF the request path, so a slow/dead/panicking
// receiver can neither block the triggering operation nor crash the
// process. Best-effort by contract: every failure is counted + audited,
// never surfaced (there is no caller to return to).
func (t *Transmitter) deliver(clientID, endpoint, auth string, req buildSETRequest) {
	defer t.wg.Done()
	// recover() so a panic (e.g. in a custom http.Client transport) is
	// contained as a delivery failure instead of taking down the goroutine.
	defer func() {
		if r := recover(); r != nil {
			t.fail(clientID, endpoint, fmt.Sprintf("panic: %v", r))
		}
	}()

	// context.Background() is the correct PARENT: the request that
	// triggered the event has already returned, so there is no live
	// request context to inherit (inheriting one would cancel the send
	// immediately). We add the per-receiver deadline so a hung receiver
	// can't pin this goroutine.
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()

	set, err := mintSET(ctx, t.signer, req, t.setTTL)
	if err != nil {
		t.fail(clientID, endpoint, "mint: "+err.Error())
		return
	}
	if err := t.post(ctx, endpoint, auth, set); err != nil {
		t.fail(clientID, endpoint, err.Error())
		return
	}
	if t.metric != nil {
		t.metric(OutcomeSuccess)
	}
}

// contentTypeSecEvent is the SSF push-delivery Content-Type for the SET body:
// the SET media type (RFC 8417 §2.3) with the application/ prefix. Derived from
// SecurityEventTokenTyp so the wire content-type and the JOSE typ header can
// never drift apart.
const contentTypeSecEvent = "application/" + SecurityEventTokenTyp

// metaReceiverEndpoint is the audit-meta key carrying the receiver URL on a
// broadcast-failure event.
const metaReceiverEndpoint = "receiver"

// post delivers the SET to the receiver. Per the SSF push-delivery
// profile the body is the compact JWS with content-type
// application/secevent+jwt. A non-2xx is an error (the SET was not
// accepted).
func (t *Transmitter) post(ctx context.Context, endpoint, auth, set string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte(set)))
	if err != nil {
		return err
	}
	httpReq.Header.Set(core.HeaderContentType, contentTypeSecEvent)
	httpReq.Header.Set("Accept", core.ContentTypeJSON)
	if auth != "" {
		httpReq.Header.Set(core.HeaderAuthorization, auth)
	}
	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain a bounded slice of the body so HTTP/1.1 connection reuse works.
	_, _ = io.CopyN(io.Discard, resp.Body, 1<<14)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("non-2xx status %d", resp.StatusCode)
}

// fail is the shared error tail: count the drop + record the internal
// caep_broadcast_failed audit event + log. Distinguishes a transport
// drop (failed) — the conventional label for "tried, did not land".
func (t *Transmitter) fail(clientID, endpoint, reason string) {
	if t.metric != nil {
		t.metric(OutcomeFailed)
	}
	if t.logger != nil {
		t.logger.Error("caep: SET delivery failed", "client_id", clientID, "endpoint", endpoint, "reason", reason)
	}
	if t.recorder != nil {
		e := &audit.Event{
			Type:     EventCAEPBroadcastFailed,
			Outcome:  audit.OutcomeFailure,
			ClientID: clientID,
			Reason:   reason,
		}
		audit.SetMeta(e, metaReceiverEndpoint, endpoint)
		t.recorder.Record(context.Background(), e)
	}
}

// Get implements audit.Sink — write-only.
func (t *Transmitter) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

// Query implements audit.Sink — write-only.
func (t *Transmitter) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

// Close drains in-flight async sends so a shutting-down server doesn't
// abandon goroutines mid-POST. Bounded by each send's own timeout.
func (t *Transmitter) Close(ctx context.Context) error {
	done := make(chan struct{})
	go func() { t.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// receiverEndpoint reads + sanity-checks the receiver URL from a client's
// registered metadata. Returns "" when unset or not a syntactically valid
// https URL — a defensive second check so a malformed value that slipped
// past create/update validation never produces an outbound POST to a
// non-https or garbage target.
func receiverEndpoint(c *core.Client) string {
	if c == nil || c.Attributes == nil {
		return ""
	}
	raw := strings.TrimSpace(c.Attributes[AttrReceiverEndpoint])
	if raw == "" {
		return ""
	}
	if ValidateReceiverEndpoint(raw) != nil {
		return ""
	}
	return raw
}

// ErrInvalidReceiverEndpoint is returned by ValidateReceiverEndpoint for
// a missing-scheme, non-https, or unparseable receiver URL.
var ErrInvalidReceiverEndpoint = errors.New("caep: receiver endpoint must be a valid https URL")

// ValidateReceiverEndpoint enforces the registration-time invariant: a
// CAEP receiver endpoint MUST be an absolute https URL with a host. Used
// at client create/update so a receiver address can never be a non-https
// (plaintext SET exfil) or relative/garbage target. Exported so the admin
// + DCR paths validate with one canonical rule.
func ValidateReceiverEndpoint(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ErrInvalidReceiverEndpoint
	}
	if u.Scheme != "https" || u.Host == "" {
		return ErrInvalidReceiverEndpoint
	}
	return nil
}

// compile-time guard: a Transmitter is an audit.Sink.
var _ audit.Sink = (*Transmitter)(nil)
