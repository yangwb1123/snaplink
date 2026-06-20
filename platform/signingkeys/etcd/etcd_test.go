package etcd

// Pure-logic tests only — no etcd server required (none is in go.mod, matching
// cluster/etcd). Covers Config default application, empty-endpoints
// validation, Announcement JSON wire roundtrip, replicaIDFromKey extraction,
// and decodeWatchEvent's branches (PUT-decodes-to-upsert,
// DELETE-maps-to-removed-with-replica-id, garbage/nil-skips).

import (
	"testing"
	"time"

	mvccpb "go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/snaplink/sso/platform/signingkeys"
	"github.com/snaplink/sso/shared/core"
)

// sampleKeys returns a realistic OKP (Ed25519) + EC (P-256) JWK pair — real
// public-key shapes, no mocks, so the wire roundtrip exercises every field
// the Server actually adopts.
func sampleKeys() []core.JWK {
	return []core.JWK{
		{
			Kty: "OKP", Use: "sig", Alg: "EdDSA", Kid: "ed-1",
			Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
		},
		{
			Kty: "EC", Use: "sig", Alg: "ES256", Kid: "ec-1",
			Crv: "P-256",
			X:   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
			Y:   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		},
	}
}

func TestNew_RequiresEndpoints(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty endpoints")
	}
}

func TestNewWithClient_AppliesDefaults(t *testing.T) {
	r := NewWithClient(nil, Config{})
	if r.prefix != DefaultPrefix {
		t.Errorf("prefix = %q, want default", r.prefix)
	}
	if r.defaultTTL != DefaultLeaseTTL {
		t.Errorf("defaultTTL = %v, want default", r.defaultTTL)
	}
}

func TestNewWithClient_KeepsExplicitConfig(t *testing.T) {
	r := NewWithClient(nil, Config{Prefix: "/x", LeaseTTL: time.Minute})
	if r.prefix != "/x" || r.defaultTTL != time.Minute {
		t.Errorf("config not preserved: %q %v", r.prefix, r.defaultTTL)
	}
}

func TestLeaseSeconds_RequestWinsThenDefaultThenFloor(t *testing.T) {
	r := NewWithClient(nil, Config{LeaseTTL: 90 * time.Second})
	if got := r.leaseSeconds(300); got != 300 {
		t.Errorf("explicit request: got %d, want 300", got)
	}
	if got := r.leaseSeconds(0); got != 90 {
		t.Errorf("default fallback: got %d, want 90", got)
	}
	// A registry whose default rounds to 0s must still floor to >=1 so etcd
	// never sees a non-positive TTL.
	r2 := &Registry{defaultTTL: 0}
	if got := r2.leaseSeconds(0); got != 1 {
		t.Errorf("floor: got %d, want 1", got)
	}
}

func TestAnnouncementJSONRoundtrip(t *testing.T) {
	in := signingkeys.Announcement{
		ReplicaID:    "replica-7",
		Keys:         sampleKeys(),
		LeaseSeconds: 300,
	}
	body, err := encodeAnnouncement(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, ok := decodeAnnouncement(body)
	if !ok {
		t.Fatal("decodeAnnouncement reported not-ok for a valid value")
	}
	if got.ReplicaID != in.ReplicaID || got.LeaseSeconds != in.LeaseSeconds {
		t.Errorf("scalar roundtrip mismatch: %+v", got)
	}
	if len(got.Keys) != len(in.Keys) {
		t.Fatalf("key count: got %d, want %d", len(got.Keys), len(in.Keys))
	}
	if got.Keys[0].Kid != "ed-1" || got.Keys[0].Crv != "Ed25519" || got.Keys[0].X == "" {
		t.Errorf("OKP key not preserved: %+v", got.Keys[0])
	}
	if got.Keys[1].Kid != "ec-1" || got.Keys[1].Y == "" {
		t.Errorf("EC key not preserved: %+v", got.Keys[1])
	}
}

func TestDecodeAnnouncement_SkipsGarbage(t *testing.T) {
	if _, ok := decodeAnnouncement([]byte("not json")); ok {
		t.Fatal("undecodable value should be skipped")
	}
}

func TestReplicaIDFromKey(t *testing.T) {
	cases := []struct {
		prefix, key, want string
	}{
		{"/snaplink/signingkeys", "/snaplink/signingkeys/replica-7", "replica-7"},
		{"/x", "/x/abc", "abc"},
		{"/snaplink/signingkeys", "/snaplink/signingkeys/", ""},
		{"/snaplink/signingkeys", "/snaplink/signingkeys", ""},
	}
	for _, c := range cases {
		if got := replicaIDFromKey(c.prefix, c.key); got != c.want {
			t.Errorf("replicaIDFromKey(%q, %q) = %q, want %q", c.prefix, c.key, got, c.want)
		}
	}
}

// TestReplicaKey covers the per-replica key derivation — the inverse of
// replicaIDFromKey, joining prefix and replica id with the path separator.
func TestReplicaKey(t *testing.T) {
	r := &Registry{prefix: "/snaplink/signingkeys"}
	if got := r.replicaKey("replica-7"); got != "/snaplink/signingkeys/replica-7" {
		t.Errorf("replicaKey = %q", got)
	}
}

// TestNamespace_TrailingSlashPreventsPrefixCollision covers the WATCH/List
// namespace: the trailing slash is what keeps prefix "/snaplink/signingkeys"
// from also matching "/snaplink/signingkeysX/...".
func TestNamespace_TrailingSlashPreventsPrefixCollision(t *testing.T) {
	r := &Registry{prefix: "/snaplink/signingkeys"}
	if got := r.namespace(); got != "/snaplink/signingkeys/" {
		t.Errorf("namespace = %q, want trailing slash", got)
	}
}

// TestDecodeWatchEvent_SkipsUnknownType covers decodeWatchEvent's default arm —
// an event type that is neither PUT nor DELETE is reported not-ok so the
// Subscribe loop drops it.
func TestDecodeWatchEvent_SkipsUnknownType(t *testing.T) {
	ev := &clientv3.Event{
		Type: mvccpb.Event_EventType(99),
		Kv:   &mvccpb.KeyValue{Key: []byte("/snaplink/signingkeys/replica-7")},
	}
	if _, ok := decodeWatchEvent(DefaultPrefix, ev); ok {
		t.Fatal("unknown event type should be skipped")
	}
}

func TestDecodeWatchEvent_PutBecomesUpsert(t *testing.T) {
	in := signingkeys.Announcement{ReplicaID: "replica-7", Keys: sampleKeys(), LeaseSeconds: 300}
	body, _ := encodeAnnouncement(in)
	ev := &clientv3.Event{
		Type: mvccpb.PUT,
		Kv:   &mvccpb.KeyValue{Key: []byte("/snaplink/signingkeys/replica-7"), Value: body},
	}
	got, ok := decodeWatchEvent(DefaultPrefix, ev)
	if !ok {
		t.Fatal("PUT should decode")
	}
	if got.Type != signingkeys.EventKeysUpserted {
		t.Errorf("type = %q, want upserted", got.Type)
	}
	if got.Announcement.ReplicaID != "replica-7" || len(got.Announcement.Keys) != 2 {
		t.Errorf("announcement not carried: %+v", got.Announcement)
	}
}

func TestDecodeWatchEvent_DeleteBecomesRemovedWithReplicaID(t *testing.T) {
	// A DELETE (lease expiry or explicit remove) carries no value; the
	// ReplicaID must come from the key path so dropAllAdopted can act.
	ev := &clientv3.Event{
		Type: mvccpb.DELETE,
		Kv:   &mvccpb.KeyValue{Key: []byte("/snaplink/signingkeys/replica-9")},
	}
	got, ok := decodeWatchEvent(DefaultPrefix, ev)
	if !ok {
		t.Fatal("DELETE should map to a removed event")
	}
	if got.Type != signingkeys.EventKeysRemoved {
		t.Errorf("type = %q, want removed", got.Type)
	}
	if got.Announcement.ReplicaID != "replica-9" {
		t.Errorf("replica id = %q, want replica-9", got.Announcement.ReplicaID)
	}
	if len(got.Announcement.Keys) != 0 {
		t.Errorf("removed event must not carry keys: %+v", got.Announcement.Keys)
	}
}

func TestDecodeWatchEvent_SkipsGarbagePut(t *testing.T) {
	ev := &clientv3.Event{
		Type: mvccpb.PUT,
		Kv:   &mvccpb.KeyValue{Key: []byte("/snaplink/signingkeys/replica-7"), Value: []byte("not json")},
	}
	if _, ok := decodeWatchEvent(DefaultPrefix, ev); ok {
		t.Fatal("undecodable PUT value should be skipped")
	}
}

func TestDecodeWatchEvent_SkipsNilKv(t *testing.T) {
	if _, ok := decodeWatchEvent(DefaultPrefix, &clientv3.Event{Type: mvccpb.PUT}); ok {
		t.Fatal("nil Kv should be skipped")
	}
	if _, ok := decodeWatchEvent(DefaultPrefix, nil); ok {
		t.Fatal("nil event should be skipped")
	}
}

func TestDecodeWatchEvent_SkipsDeleteWithBareKey(t *testing.T) {
	// A DELETE whose key has no replica segment yields no actionable id.
	ev := &clientv3.Event{Type: mvccpb.DELETE, Kv: &mvccpb.KeyValue{Key: []byte("/snaplink/signingkeys/")}}
	if _, ok := decodeWatchEvent(DefaultPrefix, ev); ok {
		t.Fatal("DELETE with no replica id should be skipped")
	}
}
