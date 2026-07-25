package caep

import (
	"context"
	"testing"
)

func TestMemoryStreamStore_CreateAndGet(t *testing.T) {
	store := NewMemoryStreamStore()
	s := &Stream{
		Issuer:  "https://sso.example.com",
		Subject: "user:alice",
		Events:  []string{"token-revocation"},
	}
	if err := store.Create(context.Background(), s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.ID == "" {
		t.Fatal("ID should be auto-generated")
	}
	got, err := store.Get(context.Background(), s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Issuer != "https://sso.example.com" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
}

func TestMemoryStreamStore_CreateDuplicate(t *testing.T) {
	store := NewMemoryStreamStore()
	s := &Stream{ID: "strm_test", Issuer: "https://example.com"}
	if err := store.Create(context.Background(), s); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := store.Create(context.Background(), s); err != ErrStreamExists {
		t.Errorf("duplicate Create: got %v, want ErrStreamExists", err)
	}
}

func TestMemoryStreamStore_GetNotFound(t *testing.T) {
	store := NewMemoryStreamStore()
	_, err := store.Get(context.Background(), "nonexistent")
	if err != ErrStreamNotFound {
		t.Errorf("Get nonexistent: got %v, want ErrStreamNotFound", err)
	}
}

func TestMemoryStreamStore_Update(t *testing.T) {
	store := NewMemoryStreamStore()
	s := &Stream{ID: "strm_upd", Subject: "user:alice"}
	_ = store.Create(context.Background(), s)

	s.Subject = "user:bob"
	if err := store.Update(context.Background(), s); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := store.Get(context.Background(), "strm_upd")
	if got.Subject != "user:bob" {
		t.Errorf("after update Subject = %q", got.Subject)
	}
}

func TestMemoryStreamStore_UpdateNotFound(t *testing.T) {
	store := NewMemoryStreamStore()
	err := store.Update(context.Background(), &Stream{ID: "nonexistent"})
	if err != ErrStreamNotFound {
		t.Errorf("Update nonexistent: got %v, want ErrStreamNotFound", err)
	}
}

func TestMemoryStreamStore_Delete(t *testing.T) {
	store := NewMemoryStreamStore()
	s := &Stream{ID: "strm_del"}
	_ = store.Create(context.Background(), s)
	if err := store.Delete(context.Background(), "strm_del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := store.Get(context.Background(), "strm_del")
	if err != ErrStreamNotFound {
		t.Error("expected ErrStreamNotFound after delete")
	}
}

func TestMemoryStreamStore_DeleteIdempotent(t *testing.T) {
	store := NewMemoryStreamStore()
	if err := store.Delete(context.Background(), "nonexistent"); err != nil {
		t.Errorf("delete absent: %v", err)
	}
}

func TestMemoryStreamStore_ListBySubject(t *testing.T) {
	store := NewMemoryStreamStore()
	_ = store.Create(context.Background(), &Stream{ID: "s1", Subject: "user:alice"})
	_ = store.Create(context.Background(), &Stream{ID: "s2", Subject: "user:bob"})
	_ = store.Create(context.Background(), &Stream{ID: "s3", Subject: "user:alice"})
	_ = store.Create(context.Background(), &Stream{ID: "s4"}) // no subject

	streams, err := store.List(context.Background(), "user:alice")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(streams) != 2 {
		t.Errorf("expected 2 streams for alice, got %d", len(streams))
	}
}

func TestMemoryStreamStore_ListAll(t *testing.T) {
	store := NewMemoryStreamStore()
	_ = store.Create(context.Background(), &Stream{ID: "s1"})
	_ = store.Create(context.Background(), &Stream{ID: "s2"})

	streams, err := store.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(streams) != 2 {
		t.Errorf("expected 2 streams, got %d", len(streams))
	}
}

func TestMemoryStreamStore_ListEmpty(t *testing.T) {
	store := NewMemoryStreamStore()
	streams, err := store.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if len(streams) != 0 {
		t.Errorf("expected 0 streams, got %d", len(streams))
	}
}

func TestMemoryStreamStore_Concurrency(t *testing.T) {
	store := NewMemoryStreamStore()
	done := make(chan struct{}, 2)
	go func() {
		for i := 0; i < 50; i++ {
			_ = store.Create(context.Background(), &Stream{Issuer: "https://example.com"})
			_, _ = store.Get(context.Background(), "nonexistent")
		}
		done <- struct{}{}
	}()
	go func() {
		for i := 0; i < 50; i++ {
			_, _ = store.List(context.Background(), "")
			_ = store.Delete(context.Background(), "nonexistent")
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func TestStreamDelivery_Fields(t *testing.T) {
	d := &StreamDelivery{
		Method:        "https://schemas.openid.net/secevent/ssf/delivery-method/push",
		Endpoint:      "https://rp.example.com/caep",
		Authorization: "Bearer token123",
	}
	if d.Method == "" {
		t.Error("Method should be set")
	}
	if d.Endpoint != "https://rp.example.com/caep" {
		t.Errorf("Endpoint = %q", d.Endpoint)
	}
}

// Adversarial: empty issuer creation
func TestAdversarial_StreamCreate_EmptyIssuer(t *testing.T) {
	store := NewMemoryStreamStore()
	s := &Stream{} // No Issuer set
	if err := store.Create(context.Background(), s); err != nil {
		t.Fatalf("Create empty: %v", err)
	}
	if s.ID == "" {
		t.Error("ID should be auto-generated even for empty stream")
	}
}

// Adversarial: get/delete after concurrent creates
func TestAdversarial_StreamCreateDeleteRace(t *testing.T) {
	store := NewMemoryStreamStore()
	s := &Stream{ID: "race_test"}
	_ = store.Create(context.Background(), s)
	// Concurrent get + delete
	done := make(chan bool, 2)
	go func() {
		_, _ = store.Get(context.Background(), "race_test")
		done <- true
	}()
	go func() {
		_ = store.Delete(context.Background(), "race_test")
		done <- true
	}()
	<-done
	<-done
}

// Adversarial: create with very long subject
func TestAdversarial_StreamCreate_LongSubject(t *testing.T) {
	store := NewMemoryStreamStore()
	longSubject := ""
	for i := 0; i < 1000; i++ {
		longSubject += "a"
	}
	s := &Stream{Subject: longSubject}
	if err := store.Create(context.Background(), s); err != nil {
		t.Fatalf("Create with long subject: %v", err)
	}
}

// Adversarial: list with SQL-like injection attempt
func TestAdversarial_StreamList_Injection(t *testing.T) {
	store := NewMemoryStreamStore()
	// Create a stream with a subject that looks like SQL injection
	_ = store.Create(context.Background(), &Stream{Subject: "' OR 1=1 --"})
	streams, err := store.List(context.Background(), "' OR 1=1 --")
	if err != nil {
		t.Fatalf("List with injection: %v", err)
	}
	if len(streams) != 1 {
		t.Errorf("expected 1 match for injection string, got %d", len(streams))
	}
}
