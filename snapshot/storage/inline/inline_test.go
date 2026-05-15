package inline_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/snapshot"
	"github.com/snaplink/sso/snapshot/storage/inline"
)

func TestRoundtrip(t *testing.T) {
	st := inline.New()
	if err := st.Put(context.Background(), "k", []byte("v")); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != "v" {
		t.Errorf("got %q want v", got)
	}
	if st.Len() != 1 {
		t.Errorf("Len=%d want 1", st.Len())
	}
}

func TestGet_Missing(t *testing.T) {
	st := inline.New()
	_, err := st.Get(context.Background(), "absent")
	if !errors.Is(err, snapshot.ErrSnapshotNotFound) {
		t.Errorf("want ErrSnapshotNotFound, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	st := inline.New()
	_ = st.Put(context.Background(), "k", []byte("v"))
	if err := st.Delete(context.Background(), "k"); err != nil {
		t.Errorf("delete: %v", err)
	}
	if st.Len() != 0 {
		t.Errorf("Len=%d after delete", st.Len())
	}
	// idempotent
	if err := st.Delete(context.Background(), "k"); err != nil {
		t.Errorf("delete missing: want nil, got %v", err)
	}
}

func TestBytesIsCopy(t *testing.T) {
	st := inline.New()
	_ = st.Put(context.Background(), "k", []byte("hello"))
	b, ok := st.Bytes("k")
	if !ok {
		t.Fatalf("Bytes returned !ok")
	}
	b[0] = 'X'
	got, _ := st.Get(context.Background(), "k")
	if string(got) != "hello" {
		t.Errorf("internal slice was mutated via Bytes(): got %q", got)
	}
}
