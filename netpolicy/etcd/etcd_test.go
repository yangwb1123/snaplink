package etcd

// Pure-logic tests only — no etcd server required. Integration tests against
// a real etcd would live behind a build tag. Covers:
//   * key path + namespace construction (trailing-slash boundary)
//   * Config default application + empty-endpoint rejection
//   * Policy JSON roundtrip
//   * translateEvent's Put-added, Put-updated, Delete-with-prevKV,
//     Delete-without-prevKV branches
//   * unmarshalPolicy stamps Version from ModRevision

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/snaplink/sso/netpolicy"
	mvccpb "go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// TestPing_NilReceiverAndClient covers the defensive guards on the
// /readyz wire — a Store whose client wasn't constructed (zero
// value) and a nil *Store both surface a typed closed-error rather
// than panic.
func TestPing_NilReceiverAndClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := (*Store)(nil).Ping(ctx); err == nil {
		t.Error("nil receiver: expected closed-error, got nil")
	}
	if err := (&Store{}).Ping(ctx); err == nil {
		t.Error("nil client: expected closed-error, got nil")
	}
}

func TestKey(t *testing.T) {
	s := &Store{prefix: "/snaplink/netpolicy"}
	if got := s.key("intranet"); got != "/snaplink/netpolicy/intranet" {
		t.Fatalf("key = %q", got)
	}
}

func TestNamespace_TrailingSlashPreventsPrefixCollision(t *testing.T) {
	s := &Store{prefix: "/snaplink/netpolicy"}
	if got := s.namespace(); got != "/snaplink/netpolicy/" {
		t.Fatalf("namespace = %q, want trailing slash", got)
	}
}

func TestNew_RequiresEndpoints(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected error when endpoints is empty")
	}
}

func TestPolicyJSONRoundtrip(t *testing.T) {
	in := netpolicy.Policy{
		Name:                "intranet",
		CIDRs:               []string{"10.0.0.0/8"},
		Hostnames:           []string{"sso.intranet.local"},
		Priority:            100,
		AdvertisedBaseURL:   "http://sso.intranet.local",
		AdvertisedJWKSURL:   "http://sso.intranet.local/.well-known/jwks.json",
		AdvertisedLogoutURL: "http://sso.intranet.local/auth/logout",
		Metadata:            map[string]string{"site": "hq"},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out netpolicy.Policy
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Name != in.Name || out.Priority != in.Priority || out.AdvertisedJWKSURL != in.AdvertisedJWKSURL {
		t.Fatalf("roundtrip mismatch: in=%+v out=%+v", in, out)
	}
	if len(out.CIDRs) != 1 || out.Metadata["site"] != "hq" {
		t.Fatalf("optional fields lost: %+v", out)
	}
}

func TestUnmarshalPolicy_StampsVersionFromModRevision(t *testing.T) {
	body, _ := json.Marshal(netpolicy.Policy{Name: "x", Version: 999})
	p, err := unmarshalPolicy(body, 42)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Version != 42 {
		t.Errorf("Version = %d, want 42 (from ModRevision)", p.Version)
	}
}

func TestTranslateEvent_Put_Added(t *testing.T) {
	body, _ := json.Marshal(netpolicy.Policy{Name: "intranet"})
	ev := &clientv3.Event{
		Type: mvccpb.PUT,
		Kv:   &mvccpb.KeyValue{Key: []byte("/p/intranet"), Value: body, CreateRevision: 5, ModRevision: 5},
	}
	got := translateEvent(ev)
	if got.Type != netpolicy.EventAdded {
		t.Errorf("type = %s, want Added", got.Type)
	}
	if got.Policy == nil || got.Policy.Name != "intranet" || got.Policy.Version != 5 {
		t.Errorf("policy = %+v", got.Policy)
	}
}

func TestTranslateEvent_Put_Updated(t *testing.T) {
	body, _ := json.Marshal(netpolicy.Policy{Name: "intranet"})
	ev := &clientv3.Event{
		Type: mvccpb.PUT,
		Kv:   &mvccpb.KeyValue{Key: []byte("/p/intranet"), Value: body, CreateRevision: 5, ModRevision: 7},
	}
	got := translateEvent(ev)
	if got.Type != netpolicy.EventUpdated {
		t.Errorf("type = %s, want Updated", got.Type)
	}
}

func TestTranslateEvent_Delete_WithPrevKV(t *testing.T) {
	body, _ := json.Marshal(netpolicy.Policy{Name: "intranet", AdvertisedBaseURL: "http://x"})
	ev := &clientv3.Event{
		Type:   mvccpb.DELETE,
		Kv:     &mvccpb.KeyValue{Key: []byte("/p/intranet")},
		PrevKv: &mvccpb.KeyValue{Key: []byte("/p/intranet"), Value: body, ModRevision: 9},
	}
	got := translateEvent(ev)
	if got.Type != netpolicy.EventRemoved {
		t.Errorf("type = %s, want Removed", got.Type)
	}
	if got.Policy == nil || got.Policy.AdvertisedBaseURL != "http://x" {
		t.Errorf("expected prev body preserved, got %+v", got.Policy)
	}
}

func TestTranslateEvent_Delete_NoPrevKV(t *testing.T) {
	ev := &clientv3.Event{
		Type:   mvccpb.DELETE,
		Kv:     &mvccpb.KeyValue{Key: []byte("/snaplink/netpolicy/intranet")},
		PrevKv: nil,
	}
	got := translateEvent(ev)
	if got.Type != netpolicy.EventRemoved {
		t.Errorf("type = %s, want Removed", got.Type)
	}
	if got.Policy == nil || got.Policy.Name != "intranet" {
		t.Errorf("expected name from key, got %+v", got.Policy)
	}
}
