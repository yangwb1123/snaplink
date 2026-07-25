package sqlite

import (
	"context"
	"testing"

	"github.com/snaplink/sso/protocols/caep"
)

func TestStreamStore_CreateGet(t *testing.T) {
	s := newStreamStore(t)
	st := &caep.Stream{ID: "s1", Issuer: "https://sso.example.com", Subject: "user:alice"}
	if err := s.Create(context.Background(), st); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(context.Background(), "s1")
	if err != nil { t.Fatalf("Get: %v", err) }
	if got.Issuer != "https://sso.example.com" { t.Errorf("Issuer = %q", got.Issuer) }
}

func TestStreamStore_NotFound(t *testing.T) {
	s := newStreamStore(t)
	_, err := s.Get(context.Background(), "nonexistent")
	if err != caep.ErrStreamNotFound { t.Errorf("got %v, want ErrStreamNotFound", err) }
}

func TestStreamStore_Update(t *testing.T) {
	s := newStreamStore(t)
	_ = s.Create(context.Background(), &caep.Stream{ID: "u1", Subject: "user:alice"})
	_ = s.Update(context.Background(), &caep.Stream{ID: "u1", Subject: "user:bob"})
	got, _ := s.Get(context.Background(), "u1")
	if got.Subject != "user:bob" { t.Errorf("Subject = %q", got.Subject) }
}

func TestStreamStore_Delete(t *testing.T) {
	s := newStreamStore(t)
	_ = s.Create(context.Background(), &caep.Stream{ID: "d1"})
	_ = s.Delete(context.Background(), "d1")
	_, err := s.Get(context.Background(), "d1")
	if err != caep.ErrStreamNotFound { t.Error("expected ErrStreamNotFound after delete") }
}

func TestStreamStore_List(t *testing.T) {
	s := newStreamStore(t)
	_ = s.Create(context.Background(), &caep.Stream{ID: "a1", Subject: "user:alice"})
	_ = s.Create(context.Background(), &caep.Stream{ID: "a2", Subject: "user:alice"})
	_ = s.Create(context.Background(), &caep.Stream{ID: "b1", Subject: "user:bob"})
	alice, _ := s.List(context.Background(), "user:alice")
	if len(alice) != 2 { t.Errorf("expected 2 for alice, got %d", len(alice)) }
	all, _ := s.List(context.Background(), "")
	if len(all) != 3 { t.Errorf("expected 3 total, got %d", len(all)) }
}

func TestStreamStore_Delivery(t *testing.T) {
	s := newStreamStore(t)
	st := &caep.Stream{ID: "del", Delivery: &caep.StreamDelivery{Method: "push", Endpoint: "https://rp.example.com/caep", Authorization: "Bearer t"}}
	_ = s.Create(context.Background(), st)
	got, _ := s.Get(context.Background(), "del")
	if got.Delivery == nil || got.Delivery.Endpoint != "https://rp.example.com/caep" {
		t.Errorf("Delivery = %+v", got.Delivery)
	}
}

func newStreamStore(t *testing.T) *StreamStore {
	t.Helper()
	s, err := NewStreamStore(t.TempDir() + "/str.db")
	if err != nil { t.Fatalf("NewStreamStore: %v", err) }
	return s
}
