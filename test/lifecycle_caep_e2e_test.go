package ssotest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/domains/userlifecycle/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/shared/core"
)

// This suite is the full-composition proof of docs/design/lifecycle-caep-events.md:
// a REAL *sso.Server wired with the user-lifecycle store, the audit recorder,
// the CAEP transmitter (with a tenant-membership store) and the
// LifecycleEventBus revoke reaction. A committed lifecycle transition must
// push exactly one signed SET to the affected tenant's opted-in client — and
// only that client — while a delivery failure stays fail-open (the transition
// commits, the failure is audited as caep_broadcast_failed). SET helpers
// (caepTrustClient / caepVerifySET / caepWaitFor) are shared with
// caep_integration_test.go.

// lifecycleReceiver records every SET body it accepts; status controls the
// response code so the same shape covers the failing-receiver case.
type lifecycleReceiver struct {
	mu     sync.Mutex
	sets   []string
	status int
}

func (r *lifecycleReceiver) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.sets = append(r.sets, string(body))
		r.mu.Unlock()
		w.WriteHeader(r.status)
	}
}

func (r *lifecycleReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sets)
}

func (r *lifecycleReceiver) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sets...)
}

// lifecycleCAEPHarness holds the composed server + stores + the TLS SET
// receiver for the suite.
type lifecycleCAEPHarness struct {
	ctx         context.Context
	users       *defaultimpl.MemoryUserProvider
	store       *memory.Store
	recorder    *audit.Recorder
	auditSink   *audit.MemorySink
	transmitter *caep.Transmitter
	issuer      *defaultimpl.Ed25519JWTIssuer
	receiver    *lifecycleReceiver
}

// newLifecycleCAEPHarness wires the full composition: user provider, tenant
// membership, tenant-scoped client store, lifecycle store, audit recorder,
// CAEP transmitter (WithTenantUserStore + failure recorder) and the server
// options that tap the transmitter into the recorder's sink chain. status is
// the SET receiver's response code (202 healthy, 500 to exercise fail-open).
func newLifecycleCAEPHarness(t *testing.T, status int) *lifecycleCAEPHarness {
	t.Helper()
	ctx := context.Background()

	recv := &lifecycleReceiver{status: status}
	srv := httptest.NewTLSServer(recv.handler())
	t.Cleanup(srv.Close)

	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "user-7"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	if err := clients.Add(ctx, &core.Client{
		ID: "affected-rp", TenantID: "tenant-T", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add affected client: %v", err)
	}
	tenants := defaultimpl.NewMemoryTenantUserStore()
	if err := tenants.Add(ctx, &core.TenantMembership{TenantID: "tenant-T", UserID: "user-7"}); err != nil {
		t.Fatalf("add membership: %v", err)
	}

	lc := memory.New()
	recSink := audit.NewMemorySink(64)
	rec := audit.New(recSink)

	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.test"))
	tx := caep.NewTransmitter(iss, clients,
		caep.WithIssuer("https://sso.test"),
		caep.WithTenantUserStore(tenants),
		caep.WithHTTPClient(caepTrustClient(srv)),
		caep.WithFailureRecorder(rec),
		caep.WithReceiverTimeout(2*time.Second),
	)

	_ = sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithUserLifecycle(lc),
		sso.WithAuditRecorder(rec),
		sso.WithCAEPTransmitter(tx),
		sso.WithTenantUserStore(tenants),
	)
	return &lifecycleCAEPHarness{
		ctx: ctx, users: users, store: lc, recorder: rec, auditSink: recSink,
		transmitter: tx, issuer: iss, receiver: recv,
	}
}

// close drains the transmitter's in-flight async sends.
func (h *lifecycleCAEPHarness) close(t *testing.T) {
	t.Helper()
	if err := h.transmitter.Close(h.ctx); err != nil {
		t.Fatalf("transmitter close: %v", err)
	}
}

// commit drives the same path the admin handler + sweep use: Store.Append
// (the transition commits) then RecordTransition (the audit event fans to
// every wired sink, CAEP transmitter included).
func (h *lifecycleCAEPHarness) commit(t *testing.T, from, to userlifecycle.State, actor string) {
	t.Helper()
	tr := userlifecycle.NewTransition(from, to, "policy", actor, time.Now())
	if err := h.store.Append(h.ctx, "user-7", tr); err != nil {
		t.Fatalf("transition append: %v", err)
	}
	userlifecycle.RecordTransition(h.ctx, h.recorder, "user-7", tr)
}

// TestLifecycleCAEPAffectedClientReceivesSET is the acceptance crux: a
// transition to a non-active state pushes exactly one JWKS-verifiable SET to
// the affected tenant's opted-in client with the right events + subject.
// ACTIVE -> SUSPENDED is legal straight from a fresh record (an account with
// no lifecycle record is implicitly active), so exactly one event fires.
func TestLifecycleCAEPAffectedClientReceivesSET(t *testing.T) {
	h := newLifecycleCAEPHarness(t, http.StatusAccepted)
	defer h.close(t)
	h.commit(t, userlifecycle.StateActive, userlifecycle.StateSuspended, "admin-1")

	caepWaitFor(t, func() bool { return h.receiver.count() >= 1 }, "affected RP receives the lifecycle SET")
	if got := h.receiver.count(); got != 1 {
		t.Fatalf("want exactly 1 SET, got %d", got)
	}
	// Resolve the SET's kid against the server's published JWKS (real trust).
	v := caepVerifySET(t, h.receiver.snapshot()[0], h.issuer)
	if len(v.aud) != 1 || v.aud[0] != "affected-rp" {
		t.Errorf("aud = %v, want [affected-rp]", v.aud)
	}
	if id, _ := v.subID["id"].(string); id != "user-7" {
		t.Errorf("sub_id.id = %q, want user-7 (the transition's target_user)", id)
	}
	if _, ok := v.events[caep.EventURIRISCAccountDisabled]; !ok {
		t.Errorf("events missing account-disabled: %v", v.events)
	}
	if _, ok := v.events[caep.EventURICAEPSessionRevoked]; !ok {
		t.Errorf("events missing session-revoked: %v", v.events)
	}
}

// TestLifecycleCAEPSweepDrivenTransitionEmits mirrors the auto-deprovision
// sweep path (actor = system): the sweep's RecordTransition must reach the
// transmitter too — one audit event, no second instrumentation point.
func TestLifecycleCAEPSweepDrivenTransitionEmits(t *testing.T) {
	h := newLifecycleCAEPHarness(t, http.StatusAccepted)
	defer h.close(t)

	activity := memory.NewActivityTracker()
	now := time.Now()
	// Dormant: last activity 40 days ago, DormantAfter 30d ⇒ ACTIVE->INACTIVE.
	activity.TouchAt("user-7", now.Add(-40*24*time.Hour))
	deps := userlifecycle.SweepDeps{
		Users:      h.users,
		Lifecycle:  h.store,
		LastActive: activity,
		Auditor:    h.recorder,
		Config:     userlifecycle.DeprovisionConfig{DormantAfter: 30 * 24 * time.Hour},
		Now:        func() time.Time { return now },
	}
	if _, err := userlifecycle.SweepOnce(h.ctx, deps); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	caepWaitFor(t, func() bool { return h.receiver.count() >= 1 }, "sweep-driven transition emits the SET")
	if got := h.receiver.count(); got != 1 {
		t.Fatalf("want exactly 1 SET from one sweep transition, got %d", got)
	}
	v := caepVerifySET(t, h.receiver.snapshot()[0], h.issuer)
	if _, ok := v.events[caep.EventURIRISCAccountDisabled]; !ok {
		t.Errorf("sweep SET missing account-disabled: %v", v.events)
	}
}

// TestLifecycleCAEPDeliveryFailureIsFailOpen proves the fail-open contract at
// the full-composition level: the transition commits and the failure is
// audited (caep_broadcast_failed) even when the receiver rejects the SET.
func TestLifecycleCAEPDeliveryFailureIsFailOpen(t *testing.T) {
	h := newLifecycleCAEPHarness(t, http.StatusInternalServerError)
	defer h.close(t)

	// The transition must commit and RecordTransition must not surface the
	// downstream delivery failure (the transmitter never blocks).
	h.commit(t, userlifecycle.StateActive, userlifecycle.StateArchived, "admin-1")

	rec, err := h.store.Get(h.ctx, "user-7")
	if err != nil || rec.State != userlifecycle.StateArchived {
		t.Fatalf("transition did not commit: state=%s err=%v", rec.State, err)
	}
	// Wait for the async delivery to fail and land the internal audit event.
	var failures []*audit.Event
	caepWaitFor(t, func() bool {
		failures, err = h.auditSink.Query(h.ctx, audit.Query{Type: caep.EventCAEPBroadcastFailed})
		if err != nil {
			t.Fatalf("query failure audit: %v", err)
		}
		return len(failures) >= 1
	}, "caep_broadcast_failed recorded after rejected delivery")
	if len(failures) != 1 {
		t.Fatalf("want 1 caep_broadcast_failed event, got %d", len(failures))
	}
	if failures[0].ClientID != "affected-rp" {
		t.Errorf("failure event ClientID = %q, want affected-rp", failures[0].ClientID)
	}
}
