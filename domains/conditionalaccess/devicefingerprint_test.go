package conditionalaccess

import (
	"context"
	"sync"
	"testing"
)

func TestMemoryDeviceFingerprint_LookupMissIsNotAnError(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryDeviceFingerprint()

	posture, ok, err := m.Lookup(ctx, "unseen-device")
	if err != nil {
		t.Fatalf("lookup miss returned error: %v", err)
	}
	if ok {
		t.Fatal("lookup miss reported ok=true")
	}
	if posture != PostureUnknown {
		t.Fatalf("lookup miss posture = %v, want PostureUnknown", posture)
	}
}

func TestMemoryDeviceFingerprint_BlankFingerprintAlwaysMisses(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryDeviceFingerprint()

	// Recording against a blank key must be a no-op — nothing to key on.
	if err := m.Record(ctx, "", PostureManaged); err != nil {
		t.Fatalf("record blank: %v", err)
	}
	if _, ok, err := m.Lookup(ctx, ""); err != nil || ok {
		t.Fatalf("lookup blank: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestMemoryDeviceFingerprint_RecordThenLookupRoundTrips(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryDeviceFingerprint()

	if err := m.Record(ctx, "fp-1", PostureManaged); err != nil {
		t.Fatalf("record: %v", err)
	}
	posture, ok, err := m.Lookup(ctx, "fp-1")
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v, want true/nil", ok, err)
	}
	if posture != PostureManaged {
		t.Fatalf("posture = %v, want PostureManaged", posture)
	}

	// Re-recording upserts (not append-only).
	if err := m.Record(ctx, "fp-1", PostureUnmanaged); err != nil {
		t.Fatalf("re-record: %v", err)
	}
	posture, ok, err = m.Lookup(ctx, "fp-1")
	if err != nil || !ok || posture != PostureUnmanaged {
		t.Fatalf("after re-record: posture=%v ok=%v err=%v, want PostureUnmanaged/true/nil", posture, ok, err)
	}

	// A distinct fingerprint that was never recorded still misses.
	if _, ok, err := m.Lookup(ctx, "fp-2"); err != nil || ok {
		t.Fatalf("unrelated fingerprint: ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestMemoryDeviceFingerprint_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryDeviceFingerprint()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = m.Record(ctx, "fp", PostureManaged)
			_, _, _ = m.Lookup(ctx, "fp")
		}(i)
	}
	wg.Wait()
}

func TestMemoryDeviceFingerprint_ImplementsInterface(t *testing.T) {
	var _ DeviceFingerprint = NewMemoryDeviceFingerprint()
}
