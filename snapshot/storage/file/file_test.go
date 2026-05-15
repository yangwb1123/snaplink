package file_test

import (
	"context"
	"errors"
	"slices"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso/snapshot"
	"github.com/snaplink/sso/snapshot/storage/file"
)

func TestPutGet(t *testing.T) {
	dir := t.TempDir()
	st, err := file.New(dir)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := st.Put(context.Background(), "snap-1", []byte("hello")); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.Get(context.Background(), "snap-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q want %q", got, "hello")
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	st, _ := file.New(dir)
	for _, n := range []string{"a", "b", "c"} {
		_ = st.Put(context.Background(), n, []byte(n))
	}
	got, err := st.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("list=%v want [a b c]", got)
	}
}

func TestDeleteIdempotent(t *testing.T) {
	dir := t.TempDir()
	st, _ := file.New(dir)
	if err := st.Delete(context.Background(), "missing"); err != nil {
		t.Errorf("delete missing: want nil, got %v", err)
	}
	_ = st.Put(context.Background(), "x", []byte("data"))
	if err := st.Delete(context.Background(), "x"); err != nil {
		t.Errorf("delete: %v", err)
	}
	if _, err := st.Get(context.Background(), "x"); !errors.Is(err, snapshot.ErrSnapshotNotFound) {
		t.Errorf("after delete: want ErrSnapshotNotFound, got %v", err)
	}
}

func TestSanitisesNames(t *testing.T) {
	dir := t.TempDir()
	st, _ := file.New(dir)
	if err := st.Put(context.Background(), "ok/with..bad chars*", []byte("z")); err != nil {
		t.Fatalf("put: %v", err)
	}
	// File on disk should have the unsafe chars replaced.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("entries=%d want 1", len(entries))
	}
	if strings.ContainsAny(entries[0].Name(), `*/`) {
		t.Errorf("unsafe chars survived: %q", entries[0].Name())
	}
	// Get under the original (un-sanitised) name still works.
	got, err := st.Get(context.Background(), "ok/with..bad chars*")
	if err != nil || string(got) != "z" {
		t.Errorf("get: %v / %q", err, got)
	}
}

func TestPutAtomic(t *testing.T) {
	dir := t.TempDir()
	st, _ := file.New(dir)
	_ = st.Put(context.Background(), "x", []byte("v1"))
	_ = st.Put(context.Background(), "x", []byte("v2"))
	got, _ := st.Get(context.Background(), "x")
	if string(got) != "v2" {
		t.Errorf("after overwrite got %q want v2", got)
	}
	// no leftover tempfiles
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("leftover tempfile: %s", e.Name())
		}
	}
}

func TestNew_RequiresBaseDir(t *testing.T) {
	if _, err := file.New(""); err == nil {
		t.Errorf("want error for empty baseDir")
	}
}

func TestBaseDirReturnsAbs(t *testing.T) {
	dir := t.TempDir()
	st, _ := file.New(dir)
	if !filepath.IsAbs(st.BaseDir()) {
		t.Errorf("BaseDir not absolute: %q", st.BaseDir())
	}
}
