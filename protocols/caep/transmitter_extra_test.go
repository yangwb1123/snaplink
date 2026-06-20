package caep_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/shared/core"
)

// These tests extend transmitter_test.go to cover the transmitter's
// option setters, the fail() tail (metric + logger + failure-audit), the
// resolveClients scope branches (no-leak edge cases), the deliver()
// error paths (mint failure, non-2xx post), the admin MetaSubject /
// MetaAffectedClient mapping, and the inert / write-only contract — all
// with REAL stores + issuers, an httptest receiver for the HTTP edge, and
// thin real-impl wrappers (NOT mocks) for error injection.

// --- error-injection wrappers (real impls that delegate, with a fail switch) ---

// errClientStore wraps a real MemoryClientStore and can be told to fail
// Get / List / ListByTenant so the transmitter's fail-open resolve paths
// are exercised. It is a real impl (delegates everything else), not a mock.
type errClientStore struct {
	*defaultimpl.MemoryClientStore
	failGet      bool
	failList     bool
	failByTenant bool
}

var errStoreBoom = errors.New("caep_test: store boom")

func (e *errClientStore) Get(ctx context.Context, id string) (*core.Client, error) {
	if e.failGet {
		return nil, errStoreBoom
	}
	return e.MemoryClientStore.Get(ctx, id)
}

func (e *errClientStore) List(ctx context.Context) ([]*core.Client, error) {
	if e.failList {
		return nil, errStoreBoom
	}
	return e.MemoryClientStore.List(ctx)
}

func (e *errClientStore) ListByTenant(ctx context.Context, tenantID string) ([]*core.Client, error) {
	if e.failByTenant {
		return nil, errStoreBoom
	}
	return e.MemoryClientStore.ListByTenant(ctx, tenantID)
}

var (
	_ core.ClientStore             = (*errClientStore)(nil)
	_ core.TenantScopedClientStore = (*errClientStore)(nil)
)

// failSigner is a JWTSigner that always errors — drives the deliver()
// mint-failure path (and mintSET's signer-side error).
type failSigner struct{}

func (failSigner) SignJWT(context.Context, string, any) (string, error) {
	return "", errors.New("caep_test: sign boom")
}

var _ caep.JWTSigner = failSigner{}

// capturingMetric records every outcome label the transmitter emits.
type capturingMetric struct {
	mu       sync.Mutex
	outcomes []string
}

func (c *capturingMetric) record(outcome string) {
	c.mu.Lock()
	c.outcomes = append(c.outcomes, outcome)
	c.mu.Unlock()
}

func (c *capturingMetric) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.outcomes...)
}

func (c *capturingMetric) has(want string) bool {
	for _, o := range c.snapshot() {
		if o == want {
			return true
		}
	}
	return false
}

// capturingLogger records error logs so the fail() logger leg is exercised.
type capturingLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *capturingLogger) Error(msg string, _ ...any) {
	l.mu.Lock()
	l.msgs = append(l.msgs, msg)
	l.mu.Unlock()
}

func (l *capturingLogger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.msgs)
}

var _ caep.Logger = (*capturingLogger)(nil)

// newTLSStatusReceiver starts an https receiver that always replies with the
// given status — used to exercise the transmitter's non-2xx failure path.
func newTLSStatusReceiver(status int) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
}

// --- option setters (zero-coverage closers) ---

func TestTransmitterOptions_AllApplied(t *testing.T) {
	t.Parallel()
	iss, store := newIssuerStore()
	rec := audit.New(audit.NewMemorySink(4))
	metric := &capturingMetric{}
	logger := &capturingLogger{}

	// Every option here is a previously-uncovered setter. Construction with
	// all of them must not panic and must yield a usable transmitter.
	tx := caep.NewTransmitter(iss, store,
		caep.WithIssuer("https://idp.test"),
		caep.WithReceiverTimeout(2*time.Second),
		caep.WithFailureRecorder(rec),
		caep.WithMetric(metric.record),
		caep.WithLogger(logger),
		caep.WithSETTTL(90*time.Second),
	)
	if tx == nil {
		t.Fatal("NewTransmitter returned nil with all options set")
	}
	// Non-positive overrides are ignored (the guards inside the setters).
	tx2 := caep.NewTransmitter(iss, store,
		caep.WithReceiverTimeout(0),
		caep.WithSETTTL(-1),
		caep.WithHTTPClient(nil),
	)
	if tx2 == nil {
		t.Fatal("NewTransmitter returned nil with no-op option values")
	}
}

// --- inert transmitter: nil signer / nil clients ⇒ Record is a silent no-op ---

func TestTransmitter_InertWhenHalfWired(t *testing.T) {
	t.Parallel()
	iss, store := newIssuerStore()
	ctx := context.Background()

	// nil signer.
	tx := caep.NewTransmitter(nil, store)
	if err := tx.Record(ctx, tenantTokensRevoked("tenant-T")); err != nil {
		t.Errorf("inert (nil signer) Record returned %v, want nil", err)
	}
	// nil clients.
	tx2 := caep.NewTransmitter(iss, nil)
	if err := tx2.Record(ctx, tenantTokensRevoked("tenant-T")); err != nil {
		t.Errorf("inert (nil clients) Record returned %v, want nil", err)
	}
}

// --- write-only audit.Sink contract: Get/Query return ErrSinkWriteOnly ---

func TestTransmitter_WriteOnlySink(t *testing.T) {
	t.Parallel()
	iss, store := newIssuerStore()
	tx := caep.NewTransmitter(iss, store)

	if _, err := tx.Get(context.Background(), "any"); !errors.Is(err, audit.ErrSinkWriteOnly) {
		t.Errorf("Get err = %v, want ErrSinkWriteOnly", err)
	}
	if _, err := tx.Query(context.Background(), audit.Query{}); !errors.Is(err, audit.ErrSinkWriteOnly) {
		t.Errorf("Query err = %v, want ErrSinkWriteOnly", err)
	}
}

// --- mapAuditEvent branches that must NOT broadcast (silent, no delivery) ---

func TestTransmitter_UnscopedMappingsAreSilent(t *testing.T) {
	t.Parallel()
	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	// A client that WOULD receive if any mapping fired.
	if err := store.Add(ctx, &core.Client{
		ID: "c", TenantID: "tenant-T", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srv)))

	cases := []*audit.Event{
		// refresh-token-reuse with NO ClientID ⇒ not mapped (no owner to push to).
		{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ActorID: "u"},
		// tenant-tokens-revoked with NO ActorID (tenant) ⇒ not mapped.
		{Type: audit.EventTenantTokensRevoked, Outcome: audit.OutcomeSuccess},
		// admin-token-revoked WITHOUT the caep_affected_client metadata ⇒ not
		// mapped (the event's own ClientID is the ADMIN's client; pushing to it
		// would be a wrong-receiver leak).
		{Type: audit.EventAdminTokenRevoked, Outcome: audit.OutcomeSuccess, ClientID: "admin-console"},
		// nil event ⇒ silent.
		nil,
	}
	for _, e := range cases {
		_ = tx.Record(ctx, e)
	}
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recv.count(); got != 0 {
		t.Fatalf("an unscoped/unmapped event broadcast %d SET(s)", got)
	}
}

// --- admin_token_revoked WITH caep_affected_client + caep_subject ⇒ delivers
// a token-revoked SET to ONLY the named affected RP, with the subject. ---

func TestTransmitter_AdminTokenRevoked_DeliversToAffectedClient(t *testing.T) {
	t.Parallel()
	recvAffected := &setReceiver{}
	srvAffected := newTLSReceiver(recvAffected)
	defer srvAffected.Close()
	recvAdmin := &setReceiver{}
	srvAdmin := newTLSReceiver(recvAdmin)
	defer srvAdmin.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "affected-rp", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srvAffected.URL},
	}); err != nil {
		t.Fatalf("add affected: %v", err)
	}
	// The admin's own client also has a receiver — it must NOT be pushed to.
	if err := store.Add(ctx, &core.Client{
		ID: "admin-console", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srvAdmin.URL},
	}); err != nil {
		t.Fatalf("add admin: %v", err)
	}

	tx := caep.NewTransmitter(iss, store,
		caep.WithIssuer("https://idp.test"),
		caep.WithHTTPClient(testHTTPClient(srvAffected, srvAdmin)))

	e := &audit.Event{Type: audit.EventAdminTokenRevoked, Outcome: audit.OutcomeSuccess, ClientID: "admin-console"}
	audit.SetMeta(e, caep.MetaAffectedClient, "affected-rp")
	audit.SetMeta(e, caep.MetaSubject, "user-99")
	_ = tx.Record(ctx, e)

	waitFor(t, func() bool { return recvAffected.count() == 1 }, "affected RP receives SET")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recvAdmin.count(); got != 0 {
		t.Fatalf("admin console (calling client) received %d SET(s) — wrong-receiver leak", got)
	}
	v := verifySET(t, recvAffected.snapshot()[0].token, iss.PublicKey())
	if len(v.aud) != 1 || v.aud[0] != "affected-rp" {
		t.Errorf("aud = %v, want [affected-rp]", v.aud)
	}
	if _, ok := v.events[caep.EventURICAEPTokenRevoked]; !ok {
		t.Errorf("events missing token-revoked: %v", v.events)
	}
	if id, _ := v.subID["id"].(string); id != "user-99" {
		t.Errorf("sub_id.id = %q, want user-99 (from caep_subject)", id)
	}
}

// --- MetaSubject overrides the mapped subject on a client-scoped event. ---

func TestTransmitter_MetaSubjectOverride(t *testing.T) {
	t.Parallel()
	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srv)))

	// refresh-token-reuse normally takes its subject from ActorID; a
	// caep_subject metadata override must win.
	e := &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "actor-default"}
	audit.SetMeta(e, caep.MetaSubject, "override-subject")
	_ = tx.Record(ctx, e)

	waitFor(t, func() bool { return recv.count() == 1 }, "SET delivered")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	v := verifySET(t, recv.snapshot()[0].token, iss.PublicKey())
	if id, _ := v.subID["id"].(string); id != "override-subject" {
		t.Errorf("sub_id.id = %q, want override-subject (MetaSubject override)", id)
	}
}

// --- client-scoped event whose affected client has NO receiver endpoint ⇒
// skipped (no delivery, no failure). ---

func TestTransmitter_ClientWithoutReceiver_Skipped(t *testing.T) {
	t.Parallel()
	iss, store := newIssuerStore()
	ctx := context.Background()
	// Owner exists but is NOT opted into Shared Signals (no endpoint attr).
	if err := store.Add(ctx, &core.Client{ID: "owner", Active: true}); err != nil {
		t.Fatalf("add: %v", err)
	}
	metric := &capturingMetric{}
	tx := caep.NewTransmitter(iss, store, caep.WithMetric(metric.record))
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Nothing delivered ⇒ no metric at all (the loop continued past the empty
	// endpoint without spawning a deliver goroutine).
	if got := metric.snapshot(); len(got) != 0 {
		t.Fatalf("a receiver-less client produced metrics %v, want none", got)
	}
}

// --- resolveClients: scopeClient with a Get error ⇒ fail-open (no delivery). ---

func TestTransmitter_ResolveClientGetError_FailOpen(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://idp.test"))
	store := &errClientStore{MemoryClientStore: defaultimpl.NewMemoryClientStore(), failGet: true}
	tx := caep.NewTransmitter(iss, store)
	// scopeClient (refresh reuse) — Get errors ⇒ resolveClients returns none.
	err := tx.Record(context.Background(), &audit.Event{
		Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u",
	})
	if err != nil {
		t.Errorf("Record returned %v, want nil (fail-open on store error)", err)
	}
	if err := tx.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// --- resolveClients: scopeTenant with a ListByTenant error ⇒ fail-open. ---

func TestTransmitter_ResolveTenantListError_FailOpen(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://idp.test"))
	store := &errClientStore{MemoryClientStore: defaultimpl.NewMemoryClientStore(), failByTenant: true}
	tx := caep.NewTransmitter(iss, store)
	if err := tx.Record(context.Background(), tenantTokensRevoked("tenant-T")); err != nil {
		t.Errorf("Record returned %v, want nil (fail-open on ListByTenant error)", err)
	}
	if err := tx.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// --- resolveClients: scopeTenant when the ClientStore is NOT tenant-scoped ⇒
// no fan-out (no broadcast-to-all). ---

// plainClientStore is a ClientStore that is deliberately NOT a
// TenantScopedClientStore: it forwards each ClientStore method explicitly
// rather than embedding, so the embedded ListByTenant is NOT promoted and
// the transmitter's tenant fan-out (which type-asserts to
// TenantScopedClientStore) stays inert.
type plainClientStore struct {
	inner *defaultimpl.MemoryClientStore
}

func (p plainClientStore) Get(ctx context.Context, id string) (*core.Client, error) {
	return p.inner.Get(ctx, id)
}
func (p plainClientStore) ValidateSecret(ctx context.Context, id, secret string) error {
	return p.inner.ValidateSecret(ctx, id, secret)
}
func (p plainClientStore) List(ctx context.Context) ([]*core.Client, error) {
	return p.inner.List(ctx)
}
func (p plainClientStore) Add(ctx context.Context, c *core.Client) error { return p.inner.Add(ctx, c) }
func (p plainClientStore) Update(ctx context.Context, c *core.Client) error {
	return p.inner.Update(ctx, c)
}
func (p plainClientStore) Delete(ctx context.Context, id string) error {
	return p.inner.Delete(ctx, id)
}
func (p plainClientStore) RotateSecret(ctx context.Context, id string) (string, error) {
	return p.inner.RotateSecret(ctx, id)
}

var _ core.ClientStore = plainClientStore{}

func TestTransmitter_TenantScope_NoTenantStore_NoFanout(t *testing.T) {
	t.Parallel()
	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://idp.test"))
	inner := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	if err := inner.Add(ctx, &core.Client{
		ID: "c", TenantID: "tenant-T", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Wrap so the type assertion to TenantScopedClientStore FAILS.
	store := plainClientStore{inner: inner}

	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srv)))
	_ = tx.Record(ctx, tenantTokensRevoked("tenant-T"))
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recv.count(); got != 0 {
		t.Fatalf("tenant event fanned out without a TenantScopedClientStore: %d SET(s)", got)
	}
}

// --- deliver: a mint failure (signer error) ⇒ failed metric + failure audit +
// logger, NEVER a success. ---

func TestTransmitter_MintFailure_FailsClosed(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	// A reachable receiver so we get PAST resolveClients to deliver().
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: "https://rp.example/ssf"},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	metric := &capturingMetric{}
	logger := &capturingLogger{}
	sink := audit.NewMemorySink(8)
	rec := audit.New(sink)
	tx := caep.NewTransmitter(failSigner{}, store,
		caep.WithMetric(metric.record),
		caep.WithLogger(logger),
		caep.WithFailureRecorder(rec))

	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})
	waitFor(t, func() bool { return metric.has(caep.OutcomeFailed) }, "failed metric recorded")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if metric.has(caep.OutcomeSuccess) {
		t.Error("mint failure recorded a success outcome")
	}
	if logger.count() == 0 {
		t.Error("mint failure did not log an error")
	}
	// The failure audit event must have been recorded.
	evs, _ := sink.Query(ctx, audit.Query{})
	var sawFail bool
	for _, e := range evs {
		if e.Type == caep.EventCAEPBroadcastFailed {
			sawFail = true
			if e.ClientID != "owner" {
				t.Errorf("failure audit ClientID = %q, want owner", e.ClientID)
			}
			if e.Metadata["receiver"] == "" {
				t.Error("failure audit missing receiver metadata")
			}
		}
	}
	if !sawFail {
		t.Errorf("no caep_broadcast_failed audit event; got %d events", len(evs))
	}
}

// --- deliver/post: a receiver that returns a non-2xx ⇒ failed metric (the SET
// was not accepted). ---

func TestTransmitter_Non2xxReceiver_Fails(t *testing.T) {
	t.Parallel()
	srv := newTLSStatusReceiver(http.StatusServiceUnavailable)
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	metric := &capturingMetric{}
	tx := caep.NewTransmitter(iss, store,
		caep.WithHTTPClient(testHTTPClient(srv)),
		caep.WithMetric(metric.record))

	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})
	waitFor(t, func() bool { return metric.has(caep.OutcomeFailed) }, "non-2xx recorded as failed")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if metric.has(caep.OutcomeSuccess) {
		t.Error("a non-2xx receiver was counted as a success")
	}
}

// --- deliver/post: a connection error (no listener) ⇒ failed metric. The
// receiver URL points at a closed server so the POST's Do() errors. ---

func TestTransmitter_UnreachableReceiver_Fails(t *testing.T) {
	t.Parallel()
	srv := newTLSReceiver(&setReceiver{})
	url := srv.URL
	pool := testHTTPClient(srv) // trust the (now-closing) cert before close
	srv.Close()                 // nothing listens at url anymore

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: url},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	metric := &capturingMetric{}
	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(pool), caep.WithMetric(metric.record))
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})
	waitFor(t, func() bool { return metric.has(caep.OutcomeFailed) }, "unreachable receiver recorded as failed")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if metric.has(caep.OutcomeSuccess) {
		t.Error("an unreachable receiver was counted as a success")
	}
}

// --- a malformed receiver endpoint that slipped past create-time validation
// is rejected at send (receiverEndpoint's defensive re-check). ---

func TestTransmitter_MalformedStoredEndpoint_Skipped(t *testing.T) {
	t.Parallel()
	iss, store := newIssuerStore()
	ctx := context.Background()
	// A plaintext (non-https) endpoint that somehow got stored: the second
	// defensive check in receiverEndpoint must drop it (no outbound POST).
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: "http://insecure.example/ssf"},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	metric := &capturingMetric{}
	tx := caep.NewTransmitter(iss, store, caep.WithMetric(metric.record))
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := metric.snapshot(); len(got) != 0 {
		t.Fatalf("a non-https stored endpoint produced delivery metrics %v", got)
	}
}

// --- Close honors a cancelled context while a send is in flight. ---

func TestTransmitter_CloseRespectsCancelledContext(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // block the in-flight send until released
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	tx := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srv)))
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})

	// Close with an already-cancelled context returns the ctx error (the send
	// is still blocked on the receiver, so the drain can't complete).
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tx.Close(cctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Close with a cancelled context = %v, want context.Canceled", err)
	}

	// Release the blocked send and drain cleanly.
	close(release)
	if err := tx.Close(context.Background()); err != nil {
		t.Errorf("final Close: %v", err)
	}
}
