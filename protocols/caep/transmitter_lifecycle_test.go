package caep_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/shared/core"
)

// lifecycleChanged builds the same audit event RecordTransition emits for a
// committed transition: EventAdminUserLifecycleChanged with target_user and
// to_state metadata (ActorID is the admin/system actor, never the affected
// user).
func lifecycleChanged(userID string, to userlifecycle.State) *audit.Event {
	e := &audit.Event{
		Type:    audit.EventAdminUserLifecycleChanged,
		Outcome: audit.OutcomeSuccess,
		ActorID: "admin-1",
	}
	audit.SetMeta(e, userlifecycle.MetaTargetUser, userID)
	audit.SetMeta(e, userlifecycle.MetaToState, string(to))
	return e
}

// addMembership puts userID into tenantID on a fresh MemoryTenantUserStore.
func addMembership(ctx context.Context, t *testing.T, tenants *defaultimpl.MemoryTenantUserStore, userID, tenantID string) {
	t.Helper()
	if err := tenants.Add(ctx, &core.TenantMembership{TenantID: tenantID, UserID: userID}); err != nil {
		t.Fatalf("add membership: %v", err)
	}
}

// addTenantClient registers clientID in tenantID with a receiver endpoint.
func addTenantClient(ctx context.Context, t *testing.T, store *defaultimpl.MemoryClientStore, clientID, tenantID, endpoint string) {
	t.Helper()
	if err := store.Add(ctx, &core.Client{
		ID: clientID, TenantID: tenantID, Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: endpoint},
	}); err != nil {
		t.Fatalf("add client %s: %v", clientID, err)
	}
}

// newLifecycleTransmitter wires the transmitter with a tenant-membership
// store + a tenant-scoped client store + the TLS receiver trust pool.
func newLifecycleTransmitter(iss *defaultimpl.Ed25519JWTIssuer, store *defaultimpl.MemoryClientStore, tenants *defaultimpl.MemoryTenantUserStore, opts ...caep.Option) *caep.Transmitter {
	all := append([]caep.Option{caep.WithTenantUserStore(tenants)}, opts...)
	return caep.NewTransmitter(iss, store, all...)
}

// TestCAEPLifecycleEventDeliversSignedSET drives an archived transition and
// asserts the affected tenant's opted-in client receives exactly one
// signature-verified SET with the account-disabled + session-revoked events
// and the target user as sub_id.
func TestCAEPLifecycleEventDeliversSignedSET(t *testing.T) {
	t.Parallel()
	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss, store := newIssuerStore()
	tenants := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()
	addMembership(ctx, t, tenants, "user-7", "tenant-T")
	addTenantClient(ctx, t, store, "client-c", "tenant-T", srv.URL)

	tx := newLifecycleTransmitter(iss, store, tenants,
		caep.WithIssuer("https://idp.test"),
		caep.WithHTTPClient(testHTTPClient(srv)))
	_ = tx.Record(ctx, lifecycleChanged("user-7", userlifecycle.StateArchived))

	waitFor(t, func() bool { return recv.count() == 1 }, "affected client receives the lifecycle SET")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	v := verifySET(t, recv.snapshot()[0].token, iss.PublicKey())
	if v.typ != caep.SecurityEventTokenTyp {
		t.Errorf("typ = %q, want %q", v.typ, caep.SecurityEventTokenTyp)
	}
	if v.iss != "https://idp.test" {
		t.Errorf("iss = %q, want https://idp.test", v.iss)
	}
	if len(v.aud) != 1 || v.aud[0] != "client-c" {
		t.Errorf("aud = %v, want [client-c]", v.aud)
	}
	if id, _ := v.subID["id"].(string); id != "user-7" {
		t.Errorf("sub_id.id = %q, want user-7 (the transition's target_user)", id)
	}
	if format, _ := v.subID["format"].(string); format != "opaque" {
		t.Errorf("sub_id.format = %q, want opaque", format)
	}
	if _, ok := v.events[caep.EventURIRISCAccountDisabled]; !ok {
		t.Errorf("events missing account-disabled: %v", v.events)
	}
	if _, ok := v.events[caep.EventURICAEPSessionRevoked]; !ok {
		t.Errorf("events missing session-revoked: %v", v.events)
	}
	if _, ok := v.events[caep.EventURIRISCAccountEnabled]; ok {
		t.Errorf("non-active transition must not emit account-enabled: %v", v.events)
	}
}

// TestCAEPLifecycleEventTenantIsolation is the tenant-dimension crux: a
// transition for a user of tenant-T must NOT reach a client of a DIFFERENT
// tenant, even when both clients have registered receivers.
func TestCAEPLifecycleEventTenantIsolation(t *testing.T) {
	t.Parallel()
	recvT := &setReceiver{}
	srvT := newTLSReceiver(recvT)
	defer srvT.Close()
	recvOther := &setReceiver{}
	srvOther := newTLSReceiver(recvOther)
	defer srvOther.Close()

	iss, store := newIssuerStore()
	tenants := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()
	addMembership(ctx, t, tenants, "user-7", "tenant-T")
	addTenantClient(ctx, t, store, "client-c", "tenant-T", srvT.URL)
	addTenantClient(ctx, t, store, "client-d", "tenant-OTHER", srvOther.URL)

	tx := newLifecycleTransmitter(iss, store, tenants,
		caep.WithHTTPClient(testHTTPClient(srvT, srvOther)))
	_ = tx.Record(ctx, lifecycleChanged("user-7", userlifecycle.StateSuspended))

	waitFor(t, func() bool { return recvT.count() == 1 }, "user's tenant client receives the SET")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recvOther.count(); got != 0 {
		t.Fatalf("cross-tenant leak: client-d in tenant-OTHER received %d SET(s) for a user of tenant-T", got)
	}
	if got := recvT.count(); got != 1 {
		t.Fatalf("client-c want 1 SET, got %d", got)
	}
}

// TestCAEPLifecycleActiveEmitsAccountEnabled drives a transition back into
// ACTIVE (reinstated suspension) and asserts the SET carries only the
// account-enabled positive signal.
func TestCAEPLifecycleActiveEmitsAccountEnabled(t *testing.T) {
	t.Parallel()
	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss, store := newIssuerStore()
	tenants := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()
	addMembership(ctx, t, tenants, "user-7", "tenant-T")
	addTenantClient(ctx, t, store, "client-c", "tenant-T", srv.URL)

	tx := newLifecycleTransmitter(iss, store, tenants,
		caep.WithHTTPClient(testHTTPClient(srv)))
	_ = tx.Record(ctx, lifecycleChanged("user-7", userlifecycle.StateActive))

	waitFor(t, func() bool { return recv.count() == 1 }, "reactivation SET delivered")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	v := verifySET(t, recv.snapshot()[0].token, iss.PublicKey())
	if _, ok := v.events[caep.EventURIRISCAccountEnabled]; !ok {
		t.Errorf("events missing account-enabled: %v", v.events)
	}
	if _, ok := v.events[caep.EventURIRISCAccountDisabled]; ok {
		t.Errorf("reactivation must not emit account-disabled: %v", v.events)
	}
	if _, ok := v.events[caep.EventURICAEPSessionRevoked]; ok {
		t.Errorf("reactivation must not emit session-revoked: %v", v.events)
	}
}

// TestCAEPLifecycleEventFailOpenDelivery proves a dead/failing receiver does
// not fail the triggering operation: Record returns nil, no SET lands, and
// the existing caep_broadcast_failed internal audit event is recorded.
func TestCAEPLifecycleEventFailOpenDelivery(t *testing.T) {
	t.Parallel()
	// Receiver answers 500 — the SET is not accepted.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	iss, store := newIssuerStore()
	tenants := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()
	addMembership(ctx, t, tenants, "user-7", "tenant-T")
	addTenantClient(ctx, t, store, "client-c", "tenant-T", srv.URL)

	failSink := audit.NewMemorySink(8)
	failRec := audit.New(failSink)
	tx := newLifecycleTransmitter(iss, store, tenants,
		caep.WithHTTPClient(testHTTPClient(srv)),
		caep.WithFailureRecorder(failRec))
	// Record must return nil — a delivery failure NEVER surfaces to the
	// transition that triggered it (fail-open by contract).
	if err := tx.Record(ctx, lifecycleChanged("user-7", userlifecycle.StateArchived)); err != nil {
		t.Fatalf("Record returned an error on a failing receiver: %v", err)
	}
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	events, err := failSink.Query(ctx, audit.Query{Type: caep.EventCAEPBroadcastFailed})
	if err != nil {
		t.Fatalf("query failure audit: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 caep_broadcast_failed event, got %d", len(events))
	}
	if events[0].ClientID != "client-c" {
		t.Errorf("failure event ClientID = %q, want client-c (the affected RP)", events[0].ClientID)
	}
}

// TestCAEPLifecycleEventUnscopedSilent locks the conservative-silence rule:
// an event whose affected clients cannot be derived MUST broadcast nothing —
// no tenant-membership store, no membership for the user, missing target_user,
// or an unrecognized to_state all resolve to zero SETs (never a
// broadcast-to-all).
func TestCAEPLifecycleEventUnscopedSilent(t *testing.T) {
	t.Parallel()
	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss, store := newIssuerStore()
	tenants := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()
	// A client that WOULD receive if any mapping fired.
	addTenantClient(ctx, t, store, "client-c", "tenant-T", srv.URL)

	// No membership store wired at all.
	noTenants := caep.NewTransmitter(iss, store, caep.WithHTTPClient(testHTTPClient(srv)))
	_ = noTenants.Record(ctx, lifecycleChanged("user-7", userlifecycle.StateArchived))

	// Wired store, but the user belongs to no tenant.
	wired := newLifecycleTransmitter(iss, store, tenants, caep.WithHTTPClient(testHTTPClient(srv)))
	_ = wired.Record(ctx, lifecycleChanged("ghost", userlifecycle.StateArchived))

	// Missing target_user metadata.
	noTarget := lifecycleChanged("user-7", userlifecycle.StateArchived)
	audit.SetMeta(noTarget, userlifecycle.MetaTargetUser, "")
	_ = wired.Record(ctx, noTarget)

	// Unrecognized / missing to_state metadata.
	_ = wired.Record(ctx, lifecycleChanged("user-7", userlifecycle.State("gibberish")))
	badState := lifecycleChanged("user-7", userlifecycle.StateArchived)
	audit.SetMeta(badState, userlifecycle.MetaToState, "")
	_ = wired.Record(ctx, badState)

	if err := noTenants.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := wired.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recv.count(); got != 0 {
		t.Fatalf("an unscoped lifecycle event broadcast %d SET(s)", got)
	}
}

// TestLifecycleBusToTransmitterSingleEmission wires the LifecycleEventBus
// AND the CAEP transmitter as sinks on one recorder and drives one
// transition: the bus reaction fires exactly once and exactly ONE SET is
// delivered — the lifecycle signal rides the single audit event, never a
// second emission channel, so there is no overlap with the revoke reaction.
func TestLifecycleBusToTransmitterSingleEmission(t *testing.T) {
	t.Parallel()
	recv := &setReceiver{}
	srv := newTLSReceiver(recv)
	defer srv.Close()

	iss, store := newIssuerStore()
	tenants := defaultimpl.NewMemoryTenantUserStore()
	ctx := context.Background()
	addMembership(ctx, t, tenants, "user-7", "tenant-T")
	addTenantClient(ctx, t, store, "client-c", "tenant-T", srv.URL)

	tx := newLifecycleTransmitter(iss, store, tenants,
		caep.WithHTTPClient(testHTTPClient(srv)))

	rec := audit.New(audit.NewMemorySink(8))
	bus := userlifecycle.NewLifecycleEventBus()
	var revocations int32
	bus.OnUserArchived(func(_ context.Context, userID string) error {
		atomic.AddInt32(&revocations, 1)
		if userID != "user-7" {
			t.Errorf("reaction userID = %q, want user-7", userID)
		}
		return nil
	})
	rec.AddSink(bus)
	rec.AddSink(tx)

	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateArchived, "policy", "admin-1", time.Now())
	userlifecycle.RecordTransition(ctx, rec, "user-7", tr)

	waitFor(t, func() bool { return recv.count() == 1 }, "one SET delivered for one transition")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if n := atomic.LoadInt32(&revocations); n != 1 {
		t.Errorf("revoke reaction fired %d time(s), want exactly 1", n)
	}
	if got := recv.count(); got != 1 {
		t.Errorf("delivered %d SET(s), want exactly 1 (no double emission)", got)
	}
}
