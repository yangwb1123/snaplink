package etcd

// Pure-logic tests only — no etcd server required. Integration tests live
// outside the unit suite (running them needs `etcd` available locally and a
// build tag). This file covers:
//   * key path construction
//   * Config default application
//   * input validation (empty endpoints)
//   * Service JSON roundtrip on the wire format
//   * translateEvent's three branches (Put-add, Put-modify, Delete)

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/registry"
	mvccpb "go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestServiceKey(t *testing.T) {
	t.Parallel()
	r := &Registry{prefix: "/snaplink/registry"}
	if got := r.serviceKey("sso", "sso-1"); got != "/snaplink/registry/sso/sso-1" {
		t.Fatalf("serviceKey = %q", got)
	}
}

func TestServiceNamespace_TrailingSlashPreventsPrefixCollision(t *testing.T) {
	t.Parallel()
	// Without the trailing slash, asking for "sso" would also match
	// "/snaplink/registry/sso-prime/...". The slash boundary prevents that.
	r := &Registry{prefix: "/snaplink/registry"}
	got := r.serviceNamespace("sso")
	if got != "/snaplink/registry/sso/" {
		t.Fatalf("serviceNamespace = %q, want trailing slash", got)
	}
}

func TestNew_RequiresEndpoints(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Error("expected error when endpoints is empty")
	}
}

func TestServiceJSONRoundtrip(t *testing.T) {
	t.Parallel()
	in := registry.Service{
		ID: "id", Name: "name", Address: "1.2.3.4", Port: 8080,
		Tags:     []string{"a", "b"},
		Metadata: map[string]string{"region": "us-west"},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out registry.Service
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ID != in.ID || out.Name != in.Name || out.Port != in.Port {
		t.Fatalf("roundtrip mismatch: in=%+v out=%+v", in, out)
	}
	if len(out.Tags) != 2 || out.Metadata["region"] != "us-west" {
		t.Fatalf("optional fields lost: %+v", out)
	}
}

func TestTranslateEvent_Put_Added(t *testing.T) {
	t.Parallel()
	svc := registry.Service{ID: "x", Name: "n"}
	body, _ := json.Marshal(svc)
	ev := &clientv3.Event{
		Type:   mvccpb.PUT,
		Kv:     &mvccpb.KeyValue{Key: []byte("/p/n/x"), Value: body, CreateRevision: 5, ModRevision: 5},
		PrevKv: nil,
	}
	got := translateEvent(ev)
	if got.Type != registry.EventAdded {
		t.Errorf("type = %s, want Added", got.Type)
	}
	if got.Service == nil || got.Service.ID != "x" {
		t.Errorf("service = %+v", got.Service)
	}
}

func TestTranslateEvent_Put_Updated(t *testing.T) {
	t.Parallel()
	svc := registry.Service{ID: "x", Name: "n"}
	body, _ := json.Marshal(svc)
	// IsModify() is true when CreateRevision != ModRevision.
	ev := &clientv3.Event{
		Type: mvccpb.PUT,
		Kv:   &mvccpb.KeyValue{Key: []byte("/p/n/x"), Value: body, CreateRevision: 5, ModRevision: 7},
	}
	got := translateEvent(ev)
	if got.Type != registry.EventUpdated {
		t.Errorf("type = %s, want Updated", got.Type)
	}
}

func TestTranslateEvent_Delete_WithPrevKV(t *testing.T) {
	t.Parallel()
	svc := registry.Service{ID: "x", Name: "n", Address: "host"}
	body, _ := json.Marshal(svc)
	ev := &clientv3.Event{
		Type:   mvccpb.DELETE,
		Kv:     &mvccpb.KeyValue{Key: []byte("/p/n/x")},
		PrevKv: &mvccpb.KeyValue{Key: []byte("/p/n/x"), Value: body},
	}
	got := translateEvent(ev)
	if got.Type != registry.EventRemoved {
		t.Errorf("type = %s, want Removed", got.Type)
	}
	if got.Service == nil || got.Service.Address != "host" {
		t.Errorf("expected previous-kv body to be preserved; got %+v", got.Service)
	}
}

// TestPing_NilReceiverAndClient covers the defensive guards on the
// /readyz wire — a Registry whose client wasn't constructed (zero
// value) and a nil *Registry both surface a typed closed-error
// rather than panic.
func TestPing_NilReceiverAndClient(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := (*Registry)(nil).Ping(ctx); err == nil {
		t.Error("nil receiver: expected closed-error, got nil")
	}
	if err := (&Registry{}).Ping(ctx); err == nil {
		t.Error("nil client: expected closed-error, got nil")
	}
}

func TestTranslateEvent_Delete_NoPrevKV_StillSurfacesIDName(t *testing.T) {
	t.Parallel()
	// When the watcher wasn't configured WithPrevKV, we should still emit
	// a Removed event with the ID and Name parsed out of the key path.
	ev := &clientv3.Event{
		Type:   mvccpb.DELETE,
		Kv:     &mvccpb.KeyValue{Key: []byte("/snaplink/registry/sso/sso-1")},
		PrevKv: nil,
	}
	got := translateEvent(ev)
	if got.Type != registry.EventRemoved {
		t.Errorf("type = %s, want Removed", got.Type)
	}
	if got.Service == nil || got.Service.ID != "sso-1" || got.Service.Name != "sso" {
		t.Errorf("expected ID/Name parsed from key, got %+v", got.Service)
	}
}

// TestNewWithClient_PrefixHandling covers both arms of NewWithClient's prefix
// defaulting (empty → DefaultPrefix, explicit → preserved) and confirms it
// initializes the lease/cancel bookkeeping maps so Register/Deregister never
// nil-panic. A nil client is fine because the constructor never touches it.
func TestNewWithClient_PrefixHandling(t *testing.T) {
	t.Parallel()
	r := NewWithClient(nil, "")
	if r.prefix != DefaultPrefix {
		t.Errorf("empty prefix = %q, want default %q", r.prefix, DefaultPrefix)
	}
	if r.leases == nil || r.cancel == nil {
		t.Error("bookkeeping maps must be initialized")
	}
	if r2 := NewWithClient(nil, "/custom/reg"); r2.prefix != "/custom/reg" {
		t.Errorf("explicit prefix = %q, want /custom/reg", r2.prefix)
	}
}

// TestTranslateEvent_Put_GarbageYieldsEmpty covers the Put branch where the
// stored value won't decode: translateEvent returns a zero Event (nil Service)
// so the Watch loop skips it.
func TestTranslateEvent_Put_GarbageYieldsEmpty(t *testing.T) {
	t.Parallel()
	ev := &clientv3.Event{
		Type: mvccpb.PUT,
		Kv:   &mvccpb.KeyValue{Key: []byte("/p/n/x"), Value: []byte("not json"), ModRevision: 1},
	}
	if got := translateEvent(ev); got.Service != nil {
		t.Errorf("undecodable PUT should yield nil Service, got %+v", got)
	}
}

// TestTranslateEvent_Delete_GarbagePrevKVYieldsEmpty covers the Delete branch
// where PrevKv is present but its value is corrupt: rather than emit a
// half-formed Removed event, translateEvent drops it (nil Service).
func TestTranslateEvent_Delete_GarbagePrevKVYieldsEmpty(t *testing.T) {
	t.Parallel()
	ev := &clientv3.Event{
		Type:   mvccpb.DELETE,
		Kv:     &mvccpb.KeyValue{Key: []byte("/p/n/x")},
		PrevKv: &mvccpb.KeyValue{Key: []byte("/p/n/x"), Value: []byte("not json")},
	}
	if got := translateEvent(ev); got.Service != nil {
		t.Errorf("undecodable PrevKv should yield nil Service, got %+v", got)
	}
}

// TestTranslateEvent_UnknownTypeYieldsEmpty covers translateEvent's default
// arm — an event type that is neither PUT nor DELETE is dropped.
func TestTranslateEvent_UnknownTypeYieldsEmpty(t *testing.T) {
	t.Parallel()
	ev := &clientv3.Event{
		Type: mvccpb.Event_EventType(99),
		Kv:   &mvccpb.KeyValue{Key: []byte("/p/n/x")},
	}
	if got := translateEvent(ev); got.Service != nil || got.Type != "" {
		t.Errorf("unknown event type should yield zero Event, got %+v", got)
	}
}

// TestDrainKeepAlive_ExitsOnClosedChannel verifies drainKeepAlive returns once
// its source channel closes — the mechanism that lets the etcd client tear down
// a lease's KeepAlive without leaking the drain goroutine. No etcd server is
// needed: we drive the channel directly.
func TestDrainKeepAlive_ExitsOnClosedChannel(t *testing.T) {
	t.Parallel()
	ch := make(chan *clientv3.LeaseKeepAliveResponse, 2)
	ch <- &clientv3.LeaseKeepAliveResponse{ID: 1}
	ch <- nil
	close(ch)

	done := make(chan struct{})
	go func() {
		defer close(done)
		drainKeepAlive(ch)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("drainKeepAlive did not return after channel close")
	}
}
