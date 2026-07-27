package defaultimpl_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"

	_ "modernc.org/sqlite"
)

// rotationLimiter is the SPI under test — both the memory and sqlite
// refresh-token stores must satisfy it identically (the conformance gate).
type rotationLimiter interface {
	RecordRotation(ctx context.Context, familyID string) (int, bool, error)
}

var (
	_ rotationLimiter = (*defaultimpl.MemoryRefreshTokenStore)(nil)
	_ rotationLimiter = (*sqlite.RefreshTokenStore)(nil)
)

// ---------- memory ----------

func TestMemoryRotationLimiter_UnderCap_NeverExceeds(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	s.MaxRotationsPerWindow = 5
	s.RotationWindow = time.Hour
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		count, exceeded, err := s.RecordRotation(ctx, "fam")
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		if count != i {
			t.Fatalf("rotation %d: count=%d want %d", i, count, i)
		}
		if exceeded {
			t.Fatalf("rotation %d: exceeded at count=%d (cap=5)", i, count)
		}
	}
}

func TestMemoryRotationLimiter_OverCap_Exceeds(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	s.MaxRotationsPerWindow = 3
	s.RotationWindow = time.Hour
	ctx := context.Background()
	var lastExceeded bool
	for i := 1; i <= 4; i++ {
		_, exceeded, err := s.RecordRotation(ctx, "fam")
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		lastExceeded = exceeded
		if i <= 3 && exceeded {
			t.Fatalf("rotation %d exceeded early (cap=3)", i)
		}
	}
	if !lastExceeded {
		t.Fatal("4th rotation should exceed cap=3")
	}
}

func TestMemoryRotationLimiter_Unconfigured_NeverExceeds(t *testing.T) {
	t.Parallel()
	// No cap/window set = limiter inert (byte-identical off). Count still
	// advances, but windowExceeded is always false.
	s := defaultimpl.NewMemoryRefreshTokenStore()
	ctx := context.Background()
	for i := 1; i <= 100; i++ {
		_, exceeded, err := s.RecordRotation(ctx, "fam")
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		if exceeded {
			t.Fatalf("unconfigured limiter exceeded at rotation %d", i)
		}
	}
}

func TestMemoryRotationLimiter_WindowRollover(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	s.MaxRotationsPerWindow = 2
	s.RotationWindow = 30 * time.Millisecond
	ctx := context.Background()
	// Burn the window to the cap.
	_, _, _ = s.RecordRotation(ctx, "fam")
	_, exceeded, _ := s.RecordRotation(ctx, "fam")
	if exceeded {
		t.Fatal("2nd rotation should be at cap, not over")
	}
	// Let the window elapse, then a fresh rotation must reset to count=1.
	time.Sleep(45 * time.Millisecond)
	count, exceeded, err := s.RecordRotation(ctx, "fam")
	if err != nil {
		t.Fatalf("post-window rotation: %v", err)
	}
	if count != 1 {
		t.Errorf("window did not roll over: count=%d want 1", count)
	}
	if exceeded {
		t.Error("post-rollover first rotation must not exceed")
	}
}

func TestMemoryRotationLimiter_EmptyFamilyIDNoOp(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	s.MaxRotationsPerWindow = 1
	s.RotationWindow = time.Hour
	count, exceeded, err := s.RecordRotation(context.Background(), "")
	if err != nil || count != 0 || exceeded {
		t.Errorf("empty familyID: got (%d, %v, %v) want (0, false, nil)", count, exceeded, err)
	}
}

func TestMemoryRotationLimiter_PerFamilyIndependent(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	s.MaxRotationsPerWindow = 2
	s.RotationWindow = time.Hour
	ctx := context.Background()
	// fam-a hits the cap.
	_, _, _ = s.RecordRotation(ctx, "fam-a")
	_, _, _ = s.RecordRotation(ctx, "fam-a")
	_, exceededA, _ := s.RecordRotation(ctx, "fam-a")
	if !exceededA {
		t.Fatal("fam-a should exceed on 3rd rotation")
	}
	// fam-b is independent — its first rotation must not be exceeded.
	count, exceededB, _ := s.RecordRotation(ctx, "fam-b")
	if count != 1 || exceededB {
		t.Errorf("fam-b polluted by fam-a: count=%d exceeded=%v", count, exceededB)
	}
}

func TestMemoryRotationLimiter_DeleteFamilyResetsWindow(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	s.MaxRotationsPerWindow = 2
	s.RotationWindow = time.Hour
	ctx := context.Background()
	_, _, _ = s.RecordRotation(ctx, "fam")
	_, _, _ = s.RecordRotation(ctx, "fam")
	if _, err := s.DeleteFamily(ctx, "fam"); err != nil {
		t.Fatalf("DeleteFamily: %v", err)
	}
	// After revocation the window is cleared — a fresh family reusing the
	// id starts at count=1.
	count, exceeded, _ := s.RecordRotation(ctx, "fam")
	if count != 1 || exceeded {
		t.Errorf("DeleteFamily did not reset window: count=%d exceeded=%v", count, exceeded)
	}
}

// ---------- sqlite ----------

func newSQLiteRotationStore(t *testing.T) *sqlite.RefreshTokenStore {
	t.Helper()
	s, err := sqlite.NewRefreshTokenStore("file:" + filepath.Join(t.TempDir(), "rot.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteRotationLimiter_UnderCap_NeverExceeds(t *testing.T) {
	t.Parallel()
	s := newSQLiteRotationStore(t)
	s.MaxRotationsPerWindow = 5
	s.RotationWindow = time.Hour
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		count, exceeded, err := s.RecordRotation(ctx, "fam")
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		if count != i {
			t.Fatalf("rotation %d: count=%d want %d", i, count, i)
		}
		if exceeded {
			t.Fatalf("rotation %d exceeded at count=%d (cap=5)", i, count)
		}
	}
}

func TestSQLiteRotationLimiter_OverCap_Exceeds(t *testing.T) {
	t.Parallel()
	s := newSQLiteRotationStore(t)
	s.MaxRotationsPerWindow = 3
	s.RotationWindow = time.Hour
	ctx := context.Background()
	var lastExceeded bool
	for i := 1; i <= 4; i++ {
		_, exceeded, err := s.RecordRotation(ctx, "fam")
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		lastExceeded = exceeded
		if i <= 3 && exceeded {
			t.Fatalf("rotation %d exceeded early (cap=3)", i)
		}
	}
	if !lastExceeded {
		t.Fatal("4th rotation should exceed cap=3")
	}
}

func TestSQLiteRotationLimiter_Unconfigured_NeverExceeds(t *testing.T) {
	t.Parallel()
	s := newSQLiteRotationStore(t)
	ctx := context.Background()
	for i := 1; i <= 50; i++ {
		_, exceeded, err := s.RecordRotation(ctx, "fam")
		if err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		if exceeded {
			t.Fatalf("unconfigured sqlite limiter exceeded at rotation %d", i)
		}
	}
}

func TestSQLiteRotationLimiter_WindowRollover(t *testing.T) {
	t.Parallel()
	s := newSQLiteRotationStore(t)
	s.MaxRotationsPerWindow = 2
	s.RotationWindow = 30 * time.Millisecond
	ctx := context.Background()
	_, _, _ = s.RecordRotation(ctx, "fam")
	_, exceeded, _ := s.RecordRotation(ctx, "fam")
	if exceeded {
		t.Fatal("2nd rotation should be at cap, not over")
	}
	time.Sleep(45 * time.Millisecond)
	count, exceeded, err := s.RecordRotation(ctx, "fam")
	if err != nil {
		t.Fatalf("post-window rotation: %v", err)
	}
	if count != 1 {
		t.Errorf("window did not roll over: count=%d want 1", count)
	}
	if exceeded {
		t.Error("post-rollover first rotation must not exceed")
	}
}

func TestSQLiteRotationLimiter_EmptyFamilyIDNoOp(t *testing.T) {
	t.Parallel()
	s := newSQLiteRotationStore(t)
	s.MaxRotationsPerWindow = 1
	s.RotationWindow = time.Hour
	count, exceeded, err := s.RecordRotation(context.Background(), "")
	if err != nil || count != 0 || exceeded {
		t.Errorf("empty familyID: got (%d, %v, %v) want (0, false, nil)", count, exceeded, err)
	}
}

func TestSQLiteRotationLimiter_DeleteFamilyResetsWindow(t *testing.T) {
	t.Parallel()
	s := newSQLiteRotationStore(t)
	s.MaxRotationsPerWindow = 2
	s.RotationWindow = time.Hour
	ctx := context.Background()
	_, _, _ = s.RecordRotation(ctx, "fam")
	_, _, _ = s.RecordRotation(ctx, "fam")
	if _, err := s.DeleteFamily(ctx, "fam"); err != nil {
		t.Fatalf("DeleteFamily: %v", err)
	}
	count, exceeded, _ := s.RecordRotation(ctx, "fam")
	if count != 1 || exceeded {
		t.Errorf("DeleteFamily did not reset window: count=%d exceeded=%v", count, exceeded)
	}
}

// ---------- memory == sqlite conformance ----------

// TestRotationLimiter_MemorySQLiteConformance drives the IDENTICAL rotation
// sequence through both backends and asserts the (count, windowExceeded)
// outputs match step-for-step — the semantics must be indistinguishable so
// an operator swapping memory→sqlite gets the same velocity behavior.
func TestRotationLimiter_MemorySQLiteConformance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const cap = 3

	mem := defaultimpl.NewMemoryRefreshTokenStore()
	mem.MaxRotationsPerWindow = cap
	mem.RotationWindow = time.Hour

	sq := newSQLiteRotationStore(t)
	sq.MaxRotationsPerWindow = cap
	sq.RotationWindow = time.Hour

	backends := map[string]rotationLimiter{"memory": mem, "sqlite": sq}

	// A scripted sequence across two families: counts and exceed flags must
	// be byte-identical between the two backends at every step.
	type step struct {
		family string
	}
	seq := []step{
		{"fam-a"}, {"fam-a"}, {"fam-a"}, {"fam-a"}, // 4 rotations, cap=3 → 4th exceeds
		{"fam-b"}, {"fam-b"}, // independent family
		{"fam-a"}, // fam-a still over cap (same window)
	}

	for i, st := range seq {
		var memCount, sqCount int
		var memEx, sqEx bool
		c, e, err := mem.RecordRotation(ctx, st.family)
		if err != nil {
			t.Fatalf("step %d memory: %v", i, err)
		}
		memCount, memEx = c, e
		c, e, err = sq.RecordRotation(ctx, st.family)
		if err != nil {
			t.Fatalf("step %d sqlite: %v", i, err)
		}
		sqCount, sqEx = c, e
		if memCount != sqCount {
			t.Errorf("step %d (%s): count memory=%d sqlite=%d", i, st.family, memCount, sqCount)
		}
		if memEx != sqEx {
			t.Errorf("step %d (%s): exceeded memory=%v sqlite=%v", i, st.family, memEx, sqEx)
		}
	}
	_ = backends
}
