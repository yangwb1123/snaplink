package scimprovision

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/webhook"
	"github.com/snaplink/sso/protocols/scim"
	"github.com/snaplink/sso/shared/core"
)

// newTestUser seeds a user directly into the UserProvider a Sink resolves
// an event's subject against (the "local" source of truth this server
// owns — distinct from the downstream fake server's own store).
func newTestUser(t *testing.T, users core.UserProvider, id, name string) {
	t.Helper()
	if err := users.CreateOrUpdate(context.Background(), &core.User{ID: id, Name: name, Email: id + "@example.com"}); err != nil {
		t.Fatalf("seed user %s: %v", id, err)
	}
}

// waitForSink closes s, which blocks until every in-flight deliver
// goroutine has returned — the deterministic way to observe an
// asynchronous Record's effects in a test.
func waitForSink(t *testing.T, s *Sink) {
	t.Helper()
	// Deliberately does NOT call s.Close(): Close cancels the Sink's shared
	// delivery context to abort in-flight work (graceful-shutdown
	// semantics), which would race with — and likely kill mid-flight — the
	// very delivery this helper is waiting to observe complete. Waiting on
	// the WaitGroup directly observes completion without disturbing it.
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Sink delivery goroutine(s) to finish")
	}
}

func TestSink_UserCreatedPushesDownstream(t *testing.T) {
	downstream, downstreamUsers, _ := newTestSCIMServer(t, "")
	_, sourceUsers, _ := newTestSCIMServer(t, "") // a second, independent UserProvider — the "local" store
	newTestUser(t, sourceUsers, "u1", "Alice")

	provisioner := newTestProvisioner(t, downstream, "")
	sink := NewSink(sourceUsers, nil, "", provisioner)

	rec := &audit.Event{Type: audit.EventAdminUserCreated}
	audit.SetMeta(rec, "subject", "u1")
	if err := sink.Record(context.Background(), rec); err != nil {
		t.Fatalf("Record: %v", err)
	}
	waitForSink(t, sink)

	all, err := downstreamUsers.List(context.Background())
	if err != nil || len(all) != 1 {
		t.Fatalf("downstream users = %v, %v; want exactly 1", all, err)
	}
	if all[0].Name != "Alice" {
		t.Fatalf("downstream user Name = %q, want Alice", all[0].Name)
	}
}

// countingProvisioner wraps a real SCIMProvisioner purely to count calls —
// used only to assert an out-of-vocabulary event never reaches it, not as a
// behavioral fake (every method still delegates to inner).
type countingProvisioner struct {
	inner SCIMProvisioner
	calls *int32
}

func (c countingProvisioner) CreateUser(ctx context.Context, u scim.Resource) (scim.Resource, error) {
	atomic.AddInt32(c.calls, 1)
	return c.inner.CreateUser(ctx, u)
}
func (c countingProvisioner) ReplaceUser(ctx context.Context, u scim.Resource) (scim.Resource, error) {
	atomic.AddInt32(c.calls, 1)
	return c.inner.ReplaceUser(ctx, u)
}
func (c countingProvisioner) DeleteUser(ctx context.Context, externalID string) error {
	atomic.AddInt32(c.calls, 1)
	return c.inner.DeleteUser(ctx, externalID)
}
func (c countingProvisioner) ReplaceGroupMembers(ctx context.Context, g scim.GroupResource) (scim.GroupResource, error) {
	atomic.AddInt32(c.calls, 1)
	return c.inner.ReplaceGroupMembers(ctx, g)
}
func (c countingProvisioner) DeleteGroup(ctx context.Context, externalID string) error {
	atomic.AddInt32(c.calls, 1)
	return c.inner.DeleteGroup(ctx, externalID)
}

var _ SCIMProvisioner = countingProvisioner{}

func TestSink_IgnoresUnrelatedEventTypes(t *testing.T) {
	var calls int32
	downstream, _, _ := newTestSCIMServer(t, "")
	provisioner := countingProvisioner{inner: newTestProvisioner(t, downstream, ""), calls: &calls}
	_, sourceUsers, _ := newTestSCIMServer(t, "")
	sink := NewSink(sourceUsers, nil, "", provisioner)

	ev := &audit.Event{Type: audit.EventType("login_success")}
	if err := sink.Record(context.Background(), ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	waitForSink(t, sink)

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("provisioner called %d times for an out-of-vocabulary event, want 0", got)
	}
}

func TestSink_UserDeletedPushesDownstreamDelete(t *testing.T) {
	downstream, downstreamUsers, _ := newTestSCIMServer(t, "")
	provisioner := newTestProvisioner(t, downstream, "")
	if _, err := provisioner.CreateUser(context.Background(), scim.Resource{ExternalID: "u9", UserName: "u9"}); err != nil {
		t.Fatalf("seed downstream: %v", err)
	}

	_, sourceUsers, _ := newTestSCIMServer(t, "")
	sink := NewSink(sourceUsers, nil, "", provisioner)

	ev := &audit.Event{Type: audit.EventAdminUserDeleted}
	audit.SetMeta(ev, "subject", "u9")
	if err := sink.Record(context.Background(), ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	waitForSink(t, sink)

	if all, _ := downstreamUsers.List(context.Background()); len(all) != 0 {
		t.Fatalf("downstream still has %d user(s) after delete event", len(all))
	}
}

// Group Sink tests target newFakeGroupSCIMServer, not newTestSCIMServer's
// real protocols/scim receiver: a permissions.Role has no externalId
// column, so the receiver can never report an existing group back on a
// filter=externalId lookup (see the comment on
// TestHTTPSCIMProvisioner_ReplaceGroupMembers_CreateThenUpdate) — using it
// here would make "did the push actually reach a resolvable group"
// unobservable via the same resolveID path production code uses.

func TestSink_GroupEventPushesFullMembership(t *testing.T) {
	downstream := newFakeGroupSCIMServer(t)
	provisioner := newTestProvisioner(t, downstream, "")

	perms := permissions.NewMemoryProvider()
	ctx := context.Background()
	if err := perms.AddRole(ctx, testGroupClientID, permissions.Role{Code: "eng", Name: "Engineering"}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := perms.AssignRoles(ctx, "user-1", testGroupClientID, []string{"eng"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}

	_, sourceUsers, _ := newTestSCIMServer(t, "")
	sink := NewSink(sourceUsers, perms, testGroupClientID, provisioner)

	ev := &audit.Event{Type: audit.EventAdminRoleAdded}
	audit.SetMeta(ev, "subject", "eng")
	if err := sink.Record(ctx, ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	waitForSink(t, sink)

	id, ok, err := provisioner.resolveID(ctx, pathGroupsRel, "eng")
	if err != nil || !ok {
		t.Fatalf("downstream group not found: ok=%v err=%v", ok, err)
	}
	if id == "" {
		t.Fatal("downstream group id is empty")
	}
}

func TestSink_GroupEventOutOfScopeClientIsSkipped(t *testing.T) {
	downstream := newFakeGroupSCIMServer(t)
	provisioner := newTestProvisioner(t, downstream, "")
	perms := permissions.NewMemoryProvider()
	ctx := context.Background()
	if err := perms.AddRole(ctx, "other-client", permissions.Role{Code: "eng", Name: "Engineering"}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}

	_, sourceUsers, _ := newTestSCIMServer(t, "")
	sink := NewSink(sourceUsers, perms, testGroupClientID, provisioner)

	// Reason format mirrors interfaces/grpcserver/grpcadmin's
	// "<client_id>/<role_code>" convention (see deliver.go groupSubject).
	ev := &audit.Event{Type: audit.EventAdminRoleAdded, Reason: "target=other-client/eng"}
	if err := sink.Record(ctx, ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	waitForSink(t, sink)

	// The event named a DIFFERENT client than this Sink's configured scope
	// — it must never have reached the downstream at all.
	_, ok, err := provisioner.resolveID(ctx, pathGroupsRel, "eng")
	if err != nil {
		t.Fatalf("resolveID: %v", err)
	}
	if ok {
		t.Fatal("out-of-scope group event leaked downstream")
	}
}

func TestSink_DeadLettersExhaustedDelivery(t *testing.T) {
	// A provisioner pointed at a closed listener always fails — every
	// attempt is a connection error, so this exercises the full retry
	// budget quickly and deterministically.
	badProvisioner := NewHTTPSCIMProvisioner("http://127.0.0.1:1")
	dlq := webhook.NewMemoryDeadLetterStore(0)
	_, sourceUsers, _ := newTestSCIMServer(t, "")
	newTestUser(t, sourceUsers, "u1", "Alice")

	sink := NewSink(sourceUsers, nil, "", badProvisioner,
		WithDeadLetterStore(dlq),
		WithDeliveryRetry(1, time.Millisecond, time.Millisecond),
	)

	ev := &audit.Event{Type: audit.EventAdminUserCreated}
	audit.SetMeta(ev, "subject", "u1")
	if err := sink.Record(context.Background(), ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	waitForSink(t, sink)

	entries, err := dlq.List(context.Background(), webhook.DeadLetterFilter{})
	if err != nil {
		t.Fatalf("dlq.List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("dead-letter entries = %d, want 1", len(entries))
	}
	if entries[0].Event.Type != audit.EventAdminUserCreated {
		t.Fatalf("dead-lettered event type = %q, want %q", entries[0].Event.Type, audit.EventAdminUserCreated)
	}
}

func TestSink_ReplayRedeliversAndClearsDeadLetter(t *testing.T) {
	downstream, downstreamUsers, _ := newTestSCIMServer(t, "")
	_, sourceUsers, _ := newTestSCIMServer(t, "")
	newTestUser(t, sourceUsers, "u1", "Alice")

	// Start pointed at an address that always fails so the first delivery
	// dead-letters, then Replay against the REAL downstream.
	failing := NewHTTPSCIMProvisioner("http://127.0.0.1:1")
	dlq := webhook.NewMemoryDeadLetterStore(0)
	sink := NewSink(sourceUsers, nil, "", failing,
		WithDeadLetterStore(dlq),
		WithDeliveryRetry(1, time.Millisecond, time.Millisecond),
	)
	ev := &audit.Event{Type: audit.EventAdminUserCreated}
	audit.SetMeta(ev, "subject", "u1")
	if err := sink.Record(context.Background(), ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	waitForSink(t, sink)
	entries, _ := dlq.List(context.Background(), webhook.DeadLetterFilter{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 dead-lettered entry, got %d", len(entries))
	}

	// Swap in a working provisioner + re-point the Sink for the replay.
	sink.provisioner = newTestProvisioner(t, downstream, "")
	if _, err := sink.Replay(context.Background(), entries[0].ID); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if _, err := dlq.Get(context.Background(), entries[0].ID); err == nil {
		t.Fatal("dead-letter entry still present after successful replay")
	}
	if all, _ := downstreamUsers.List(context.Background()); len(all) != 1 {
		t.Fatalf("downstream users after replay = %d, want 1", len(all))
	}
}

func TestSubjectIDConventions(t *testing.T) {
	cases := []struct {
		name string
		ev   audit.Event
		want string
	}{
		{"scim subject meta", audit.Event{Metadata: map[string]string{"subject": "u1"}}, "u1"},
		{"admin target_user meta", audit.Event{Metadata: map[string]string{"target_user": "u2"}}, "u2"},
		{"grpcadmin reason prefix", audit.Event{Reason: "target=u3"}, "u3"},
		{"no known convention", audit.Event{Reason: "unrelated"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := subjectID(c.ev); got != c.want {
				t.Errorf("subjectID(%+v) = %q, want %q", c.ev, got, c.want)
			}
		})
	}
}

func TestGroupSubjectConventions(t *testing.T) {
	t.Run("scim subject meta is bare role code", func(t *testing.T) {
		ev := audit.Event{Metadata: map[string]string{"subject": "eng"}}
		clientID, roleCode, ok := groupSubject(ev)
		if !ok || clientID != "" || roleCode != "eng" {
			t.Errorf("groupSubject = (%q, %q, %v), want (\"\", \"eng\", true)", clientID, roleCode, ok)
		}
	})
	t.Run("grpcadmin reason is client/role", func(t *testing.T) {
		ev := audit.Event{Reason: "target=client1/eng"}
		clientID, roleCode, ok := groupSubject(ev)
		if !ok || clientID != "client1" || roleCode != "eng" {
			t.Errorf("groupSubject = (%q, %q, %v), want (\"client1\", \"eng\", true)", clientID, roleCode, ok)
		}
	})
	t.Run("no known convention", func(t *testing.T) {
		if _, _, ok := groupSubject(audit.Event{Reason: "unrelated"}); ok {
			t.Error("groupSubject matched an unrelated Reason string")
		}
	})
}
