package redis

import (
	"context"
	"testing"
	"time"
)

func TestRecordRotationEmptyFamilyIsNoOp(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb)
	count, exceeded, err := s.RecordRotation(context.Background(), "")
	if err != nil || count != 0 || exceeded {
		t.Fatalf("empty family: got (%d, %v, %v), want (0, false, nil)", count, exceeded, err)
	}
}

func TestRecordRotationCountsAndCaps(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	// Cap: at most 3 rotations of a family per (long) window.
	s := NewRefreshTokenStore(rdb, WithRotationCap(3, time.Hour))
	ctx := context.Background()

	for want := 1; want <= 3; want++ {
		count, exceeded, err := s.RecordRotation(ctx, "famA")
		if err != nil {
			t.Fatalf("rotation %d: %v", want, err)
		}
		if count != want {
			t.Fatalf("rotation %d: count=%d, want %d", want, count, want)
		}
		if exceeded {
			t.Fatalf("rotation %d: exceeded too early", want)
		}
	}
	// The 4th rotation in-window crosses the cap.
	count, exceeded, err := s.RecordRotation(ctx, "famA")
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 || !exceeded {
		t.Fatalf("4th rotation: got (count=%d, exceeded=%v), want (4, true)", count, exceeded)
	}

	// A different family is counted independently.
	count, exceeded, err = s.RecordRotation(ctx, "famB")
	if err != nil || count != 1 || exceeded {
		t.Fatalf("famB first rotation: got (%d, %v, %v), want (1, false, nil)", count, exceeded, err)
	}
}

func TestRecordRotationNoCapNeverExceeds(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewRefreshTokenStore(rdb) // no WithRotationCap -> cap disabled
	ctx := context.Background()
	for i := 1; i <= 50; i++ {
		count, exceeded, err := s.RecordRotation(ctx, "fam")
		if err != nil {
			t.Fatal(err)
		}
		if count != i {
			t.Fatalf("rotation %d: count=%d", i, count)
		}
		if exceeded {
			t.Fatalf("rotation %d: cap disabled must never report exceeded", i)
		}
	}
}

func TestRecordRotationWindowRollsOver(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	// Tiny window so a short real sleep guarantees rollover.
	s := NewRefreshTokenStore(rdb, WithRotationCap(2, 10*time.Millisecond))
	ctx := context.Background()

	if c, _, err := s.RecordRotation(ctx, "fam"); err != nil || c != 1 {
		t.Fatalf("first: count=%d err=%v", c, err)
	}
	if c, _, err := s.RecordRotation(ctx, "fam"); err != nil || c != 2 {
		t.Fatalf("second: count=%d err=%v", c, err)
	}

	time.Sleep(20 * time.Millisecond) // past the window

	c, exceeded, err := s.RecordRotation(ctx, "fam")
	if err != nil {
		t.Fatal(err)
	}
	if c != 1 || exceeded {
		t.Fatalf("after window: got (count=%d, exceeded=%v), want (1, false) — window did not roll over", c, exceeded)
	}
}
