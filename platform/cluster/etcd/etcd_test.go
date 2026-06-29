package etcd

// Pure-logic tests only — no etcd server required. Covers Config default
// application, empty-endpoints validation, Event JSON wire roundtrip,
// eventKey shape, and decodeEvent's branches (PUT-decodes, DELETE-skips,
// garbage-skips).

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/cluster"
	mvccpb "go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestNew_RequiresEndpoints(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty endpoints")
	}
}

func TestNewWithClient_AppliesDefaults(t *testing.T) {
	t.Parallel()
	b := NewWithClient(nil, Config{})
	if b.prefix != DefaultPrefix {
		t.Errorf("prefix = %q, want default", b.prefix)
	}
	if b.eventTTL != DefaultEventTTL {
		t.Errorf("eventTTL = %v, want default", b.eventTTL)
	}
}

func TestNewWithClient_KeepsExplicitConfig(t *testing.T) {
	t.Parallel()
	b := NewWithClient(nil, Config{Prefix: "/x", EventTTL: time.Minute})
	if b.prefix != "/x" || b.eventTTL != time.Minute {
		t.Errorf("config not preserved: %q %v", b.prefix, b.eventTTL)
	}
}

func TestEventKey_UniqueAndPrefixed(t *testing.T) {
	t.Parallel()
	b := &Bus{prefix: DefaultPrefix}
	k1, err := b.eventKey()
	if err != nil {
		t.Fatalf("eventKey: %v", err)
	}
	k2, _ := b.eventKey()
	if k1 == k2 {
		t.Fatal("eventKey collided")
	}
	if !strings.HasPrefix(k1, DefaultPrefix+"/") {
		t.Errorf("key %q not under prefix", k1)
	}
}

func TestEventJSONRoundtrip(t *testing.T) {
	t.Parallel()
	in := cluster.Event{
		Kind:    cluster.KindTenantSuspension,
		Key:     "tenant-9",
		Payload: map[string]string{"reason": "admin"},
	}
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ev := &clientv3.Event{Type: mvccpb.PUT, Kv: &mvccpb.KeyValue{Value: body}}
	got, ok := decodeEvent(ev)
	if !ok {
		t.Fatal("decodeEvent reported not-ok for a valid PUT")
	}
	if got.Kind != in.Kind || got.Key != in.Key || got.Payload["reason"] != "admin" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}

func TestDecodeEvent_SkipsDelete(t *testing.T) {
	t.Parallel()
	ev := &clientv3.Event{Type: mvccpb.DELETE, Kv: &mvccpb.KeyValue{}}
	if _, ok := decodeEvent(ev); ok {
		t.Fatal("DELETE should be skipped")
	}
}

func TestDecodeEvent_SkipsGarbage(t *testing.T) {
	t.Parallel()
	ev := &clientv3.Event{Type: mvccpb.PUT, Kv: &mvccpb.KeyValue{Value: []byte("not json")}}
	if _, ok := decodeEvent(ev); ok {
		t.Fatal("undecodable value should be skipped")
	}
}

func TestDecodeEvent_NilKv(t *testing.T) {
	t.Parallel()
	if _, ok := decodeEvent(&clientv3.Event{Type: mvccpb.PUT}); ok {
		t.Fatal("nil Kv should be skipped")
	}
}
