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
	"encoding/json"
	"testing"

	"github.com/snaplink/sso/registry"
	clientv3 "go.etcd.io/etcd/client/v3"
	mvccpb "go.etcd.io/etcd/api/v3/mvccpb"
)

func TestServiceKey(t *testing.T) {
	r := &Registry{prefix: "/snaplink/registry"}
	if got := r.serviceKey("sso", "sso-1"); got != "/snaplink/registry/sso/sso-1" {
		t.Fatalf("serviceKey = %q", got)
	}
}

func TestServiceNamespace_TrailingSlashPreventsPrefixCollision(t *testing.T) {
	// Without the trailing slash, asking for "sso" would also match
	// "/snaplink/registry/sso-prime/...". The slash boundary prevents that.
	r := &Registry{prefix: "/snaplink/registry"}
	got := r.serviceNamespace("sso")
	if got != "/snaplink/registry/sso/" {
		t.Fatalf("serviceNamespace = %q, want trailing slash", got)
	}
}

func TestNew_RequiresEndpoints(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected error when endpoints is empty")
	}
}

func TestServiceJSONRoundtrip(t *testing.T) {
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

func TestTranslateEvent_Delete_NoPrevKV_StillSurfacesIDName(t *testing.T) {
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
