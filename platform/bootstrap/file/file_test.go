package file

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/snaplink/sso/platform/bootstrap"
)

func tempState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "bootstrap.json")
}

func TestTracker_RejectsEmptyPath(t *testing.T) {
	t.Parallel()
	if _, err := New(""); err == nil {
		t.Error("expected error on empty path")
	}
}

func TestTracker_MissingFileStartsEmpty(t *testing.T) {
	t.Parallel()
	tr, err := New(tempState(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = tr.Close() }()
	v, _ := tr.AppliedVersion(context.Background(), "ns")
	if v != 0 {
		t.Errorf("v = %d, want 0 for missing file", v)
	}
}

func TestTracker_PersistsAcrossInstances(t *testing.T) {
	t.Parallel()
	path := tempState(t)
	ctx := context.Background()

	tr1, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, v := range []int{1, 2, 3} {
		if err := tr1.MarkApplied(ctx, "sso-server", v, "step"); err != nil {
			t.Fatalf("MarkApplied(%d): %v", v, err)
		}
	}
	_ = tr1.Close()

	// Second instance must observe the watermark.
	tr2, err := New(path)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	defer func() { _ = tr2.Close() }()
	got, _ := tr2.AppliedVersion(ctx, "sso-server")
	if got != 3 {
		t.Errorf("after reload: got %d, want 3", got)
	}
}

func TestTracker_StateFileShape(t *testing.T) {
	t.Parallel()
	path := tempState(t)
	tr, _ := New(path)
	_ = tr.MarkApplied(context.Background(), "billing-app", 2, "seed_admin")
	_ = tr.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	// Sanity-check the shape rather than the bytes — JSON ordering is
	// unspecified but the field names + nesting are part of the contract.
	var parsed struct {
		Namespaces map[string]struct {
			Version int `json:"version"`
			Applied []struct {
				V      int    `json:"v"`
				Name   string `json:"name"`
				AtUnix int64  `json:"at_unix"`
			} `json:"applied"`
		} `json:"namespaces"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("state file not valid JSON of expected shape: %v\n%s", err, data)
	}
	ns, ok := parsed.Namespaces["billing-app"]
	if !ok {
		t.Fatalf("billing-app missing from state: %s", data)
	}
	if ns.Version != 2 || len(ns.Applied) != 1 || ns.Applied[0].Name != "seed_admin" {
		t.Errorf("namespace state = %+v", ns)
	}
	if ns.Applied[0].AtUnix == 0 {
		t.Error("at_unix should be populated")
	}
}

func TestTracker_MonotonicVersion(t *testing.T) {
	t.Parallel()
	tr, _ := New(tempState(t))
	defer func() { _ = tr.Close() }()
	ctx := context.Background()

	_ = tr.MarkApplied(ctx, "ns", 5, "five")
	_ = tr.MarkApplied(ctx, "ns", 2, "two") // out-of-order; must not regress

	v, _ := tr.AppliedVersion(ctx, "ns")
	if v != 5 {
		t.Errorf("v = %d, want 5 (lower-version mark must not regress)", v)
	}
}

func TestTracker_NamespacesIsolated(t *testing.T) {
	t.Parallel()
	tr, _ := New(tempState(t))
	defer func() { _ = tr.Close() }()
	ctx := context.Background()

	_ = tr.MarkApplied(ctx, "a", 7, "step")
	_ = tr.MarkApplied(ctx, "b", 1, "step")

	if v, _ := tr.AppliedVersion(ctx, "a"); v != 7 {
		t.Errorf("ns a = %d", v)
	}
	if v, _ := tr.AppliedVersion(ctx, "b"); v != 1 {
		t.Errorf("ns b = %d", v)
	}
	if v, _ := tr.AppliedVersion(ctx, "missing"); v != 0 {
		t.Errorf("ns missing = %d", v)
	}
}

func TestTracker_AtomicWrite_NoTempLeftBehind(t *testing.T) {
	t.Parallel()
	path := tempState(t)
	tr, _ := New(path)
	for i := 1; i <= 5; i++ {
		_ = tr.MarkApplied(context.Background(), "ns", i, "step")
	}
	_ = tr.Close()

	// Only the canonical state file should remain in the dir; no temp leftovers.
	entries, _ := os.ReadDir(filepath.Dir(path))
	base := filepath.Base(path)
	for _, e := range entries {
		if e.Name() == base {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}

func TestTracker_CorruptFile_FailsFast(t *testing.T) {
	t.Parallel()
	path := tempState(t)
	if err := os.WriteFile(path, []byte("not json at all"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if _, err := New(path); err == nil {
		t.Error("expected parse error on corrupt state file")
	}
}

func TestTracker_EmptyFileLoadsAsEmpty(t *testing.T) {
	t.Parallel()
	path := tempState(t)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	tr, err := New(path)
	if err != nil {
		t.Fatalf("New (empty file): %v", err)
	}
	defer func() { _ = tr.Close() }()
	if v, _ := tr.AppliedVersion(context.Background(), "ns"); v != 0 {
		t.Errorf("v = %d on empty file", v)
	}
}

func TestTracker_CreatesMissingDir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "nested", "deep", "bootstrap.json")
	tr, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = tr.Close() }()
	if err := tr.MarkApplied(context.Background(), "ns", 1, "step"); err != nil {
		t.Fatalf("MarkApplied: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("state file not created: %v", err)
	}
}

func TestTracker_ConcurrentMarksSerialized(t *testing.T) {
	t.Parallel()
	tr, _ := New(tempState(t))
	defer func() { _ = tr.Close() }()
	ctx := context.Background()
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 1; i <= n; i++ {
		go func(v int) {
			defer wg.Done()
			_ = tr.MarkApplied(ctx, "ns", v, "step")
		}(i)
	}
	wg.Wait()
	if v, _ := tr.AppliedVersion(ctx, "ns"); v != n {
		t.Errorf("after concurrent marks: v = %d, want %d", v, n)
	}
}

func TestTracker_SatisfiesInterface(t *testing.T) {
	t.Parallel()
	tr, _ := New(tempState(t))
	defer func() { _ = tr.Close() }()
	var _ bootstrap.Tracker = tr
}
