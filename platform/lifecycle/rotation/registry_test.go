package rotation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core/corecredential"
)

const testCredType corecredential.CredentialType = "test_cred"

// fakeRotator is a minimal corecredential.CredentialRotator test double.
// Rotate returns the next queued result (success meta or failErr) so tests
// can script a rotation sequence without any real crypto/IO.
type fakeRotator struct {
	overlap time.Duration
	version int
	failErr error // when set, the NEXT Rotate call fails and clears this field
}

func (f *fakeRotator) Type() corecredential.CredentialType { return testCredType }
func (f *fakeRotator) OverlapWindow() time.Duration         { return f.overlap }
func (f *fakeRotator) Rotate(context.Context) (corecredential.CredentialMeta, error) {
	if f.failErr != nil {
		err := f.failErr
		f.failErr = nil
		return corecredential.CredentialMeta{}, err
	}
	f.version++
	return corecredential.CredentialMeta{
		ID:      testCredID(f.version),
		Type:    testCredType,
		Version: f.version,
		Status:  corecredential.CredentialStatusActive,
	}, nil
}

func testCredID(v int) string {
	return string(testCredType) + "/v" + string(rune('0'+v))
}

func TestRegistry_RegisterRejectsInvalidInput(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(nil, time.Hour); err == nil {
		t.Fatal("Register(nil rotator) should error")
	}
	if err := reg.Register(&fakeRotator{}, 0); err == nil {
		t.Fatal("Register(non-positive interval) should error")
	}
	if err := reg.Register(&fakeRotator{}, -time.Second); err == nil {
		t.Fatal("Register(negative interval) should error")
	}
}

func TestRegistry_RegisterRejectsDuplicateType(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&fakeRotator{}, time.Hour); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err := reg.Register(&fakeRotator{}, time.Hour)
	if !errors.Is(err, ErrDuplicateRotator) {
		t.Fatalf("second Register(same type) = %v, want ErrDuplicateRotator", err)
	}
}

// TestRegistry_DueTiming proves the core scheduling contract: Register
// schedules the FIRST rotation one full interval out (not immediately), due()
// fires at/after nextDue and not before, and applySuccess reschedules the
// next due time exactly interval after the rotation instant (not after wall
// time.Now(), so the math is deterministic under a fake clock).
func TestRegistry_DueTiming(t *testing.T) {
	reg := NewRegistry()
	interval := 10 * time.Minute
	if err := reg.Register(&fakeRotator{}, interval); err != nil {
		t.Fatalf("Register: %v", err)
	}

	t0 := time.Now()
	// Freshly registered: nothing is due before a full interval elapses.
	if got := reg.due(t0.Add(interval - time.Second)); len(got) != 0 {
		t.Fatalf("due() one second early = %d entries, want 0", len(got))
	}
	// Exactly at nextDue: due (the contract is !now.Before(nextDue), i.e. >=).
	due := reg.due(t0.Add(interval))
	if len(due) != 1 {
		t.Fatalf("due() at nextDue = %d entries, want 1", len(due))
	}

	// Apply the rotation at t0+interval and confirm the NEXT due time is
	// exactly interval later — scheduling is relative to the rotation
	// instant passed in, not to wall-clock time.Now() read again internally.
	rotateAt := t0.Add(interval)
	meta := corecredential.CredentialMeta{ID: "v1", Type: testCredType, Version: 1}
	_, next := reg.applySuccess(testCredType, meta, rotateAt)
	wantNext := rotateAt.Add(interval)
	if !next.Equal(wantNext) {
		t.Fatalf("next due = %v, want %v", next, wantNext)
	}
	if got := reg.due(next.Add(-time.Second)); len(got) != 0 {
		t.Fatalf("due() one second before the rescheduled due time = %d entries, want 0", len(got))
	}
	if got := reg.due(next); len(got) != 1 {
		t.Fatalf("due() at the rescheduled due time = %d entries, want 1", len(got))
	}
}

// TestRegistry_ApplySuccessDemotesPrevious proves the overlap-window
// handoff: the SECOND rotation demotes the first version into Retiring with
// NotAfter = rotationTime + OverlapWindow, while the new version becomes
// Active — the framework never leaves the class with only a bare "current"
// and no record of what receivers may still be validating against.
func TestRegistry_ApplySuccessDemotesPrevious(t *testing.T) {
	reg := NewRegistry()
	overlap := 5 * time.Minute
	rotator := &fakeRotator{overlap: overlap}
	if err := reg.Register(rotator, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}

	now := time.Now()
	first := corecredential.CredentialMeta{ID: "v1", Type: testCredType, Version: 1}
	if demoted, _ := reg.applySuccess(testCredType, first, now); demoted != nil {
		t.Fatalf("first rotation demoted %+v, want nil (no previous version existed)", demoted)
	}

	second := corecredential.CredentialMeta{ID: "v2", Type: testCredType, Version: 2}
	rotateAt := now.Add(time.Hour)
	demoted, _ := reg.applySuccess(testCredType, second, rotateAt)
	if demoted == nil {
		t.Fatal("second rotation should demote the first version, got nil")
	}
	if demoted.Version != 1 || demoted.Status != corecredential.CredentialStatusRetiring {
		t.Fatalf("demoted = %+v, want version 1 status retiring", demoted)
	}
	wantNotAfter := rotateAt.Add(overlap)
	if !demoted.NotAfter.Equal(wantNotAfter) {
		t.Fatalf("demoted.NotAfter = %v, want %v", demoted.NotAfter, wantNotAfter)
	}

	active := reg.activeMetas()
	if len(active) != 1 || active[0].Version != 2 {
		t.Fatalf("activeMetas() = %+v, want just version 2 active", active)
	}
}

// TestRegistry_ApplyFailureKeepsOldCredentialServing is the failure-mode
// invariant from AGENTS.md §3 (Fail-Closed/Fail-Open table) applied to
// rotation: a failed Rotate must NEVER clear or touch the currently-serving
// credential — only the retry schedule changes.
func TestRegistry_ApplyFailureKeepsOldCredentialServing(t *testing.T) {
	reg := NewRegistry()
	rotator := &fakeRotator{}
	if err := reg.Register(rotator, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	now := time.Now()
	installed := corecredential.CredentialMeta{ID: "v1", Type: testCredType, Version: 1, Status: corecredential.CredentialStatusActive}
	reg.applySuccess(testCredType, installed, now)

	failAt := now.Add(time.Hour)
	failures, next := reg.applyFailure(testCredType, failAt, time.Minute, 15*time.Minute)
	if failures != 1 {
		t.Fatalf("failures = %d, want 1", failures)
	}
	if want := failAt.Add(time.Minute); !next.Equal(want) {
		t.Fatalf("next retry = %v, want %v (base backoff)", next, want)
	}

	active := reg.activeMetas()
	if len(active) != 1 || active[0].Version != 1 || active[0].ID != "v1" {
		t.Fatalf("activeMetas() after a failed rotation = %+v, want the pre-existing v1 untouched", active)
	}
}

func TestRegistry_ApplyFailureBacksOffAndCaps(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&fakeRotator{}, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	base, maxDelay := time.Minute, 4*time.Minute
	now := time.Now()

	// failures: 1 -> base, 2 -> 2*base, 3 -> 4*base==cap, 4 -> still capped.
	wantDelays := []time.Duration{base, 2 * base, 4 * base, 4 * base}
	for i, want := range wantDelays {
		failures, next := reg.applyFailure(testCredType, now, base, maxDelay)
		if failures != i+1 {
			t.Fatalf("iteration %d: failures = %d, want %d", i, failures, i+1)
		}
		if got := next.Sub(now); got != want {
			t.Fatalf("iteration %d: backoff = %v, want %v", i, got, want)
		}
	}
}

func TestRegistry_RetireDueTransitionsStatus(t *testing.T) {
	reg := NewRegistry()
	overlap := time.Minute
	rotator := &fakeRotator{overlap: overlap}
	if err := reg.Register(rotator, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	now := time.Now()
	reg.applySuccess(testCredType, corecredential.CredentialMeta{ID: "v1", Type: testCredType, Version: 1}, now)
	reg.applySuccess(testCredType, corecredential.CredentialMeta{ID: "v2", Type: testCredType, Version: 2}, now.Add(time.Hour))

	// Still inside the overlap window: nothing retires yet.
	if out := reg.retireDue(now.Add(time.Hour).Add(overlap - time.Second)); len(out) != 0 {
		t.Fatalf("retireDue() inside the overlap window = %d, want 0", len(out))
	}
	// Past NotAfter: the demoted v1 retires.
	out := reg.retireDue(now.Add(time.Hour).Add(overlap))
	if len(out) != 1 || out[0].Version != 1 || out[0].Status != corecredential.CredentialStatusRetired {
		t.Fatalf("retireDue() past NotAfter = %+v, want v1 retired", out)
	}
	// Idempotent: a second call finds nothing left to retire.
	if out := reg.retireDue(now.Add(24 * time.Hour)); len(out) != 0 {
		t.Fatalf("retireDue() after the retiring slot was cleared = %d, want 0", len(out))
	}
}

func TestRegistry_InventoryReflectsCurrentAndRetiring(t *testing.T) {
	reg := NewRegistry()
	overlap := time.Minute
	rotator := &fakeRotator{overlap: overlap}
	if err := reg.Register(rotator, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	now := time.Now()
	active := corecredential.CredentialStatusActive
	reg.applySuccess(testCredType, corecredential.CredentialMeta{ID: "v1", Type: testCredType, Version: 1, Status: active}, now)
	reg.applySuccess(testCredType, corecredential.CredentialMeta{ID: "v2", Type: testCredType, Version: 2, Status: active}, now.Add(time.Hour))

	inv := reg.Inventory()
	if len(inv) != 2 {
		t.Fatalf("Inventory() = %d entries, want 2 (active v2 + retiring v1)", len(inv))
	}
	byVersion := map[int]InventoryEntry{}
	for _, e := range inv {
		byVersion[e.Version] = e
	}
	if byVersion[2].Status != corecredential.CredentialStatusActive {
		t.Fatalf("v2 status = %q, want active", byVersion[2].Status)
	}
	if byVersion[1].Status != corecredential.CredentialStatusRetiring {
		t.Fatalf("v1 status = %q, want retiring", byVersion[1].Status)
	}
}

func TestRegistry_CurrentMetaProviderSeedsInventoryBeforeFirstRotation(t *testing.T) {
	reg := NewRegistry()
	seeded := corecredential.CredentialMeta{ID: "seed/v1", Type: testCredType, Version: 1, Status: corecredential.CredentialStatusActive}
	if err := reg.Register(&seededRotator{fakeRotator: fakeRotator{}, meta: seeded}, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	inv := reg.Inventory()
	if len(inv) != 1 || inv[0].ID != seeded.ID {
		t.Fatalf("Inventory() = %+v, want the CurrentMetaProvider-seeded version before any rotation", inv)
	}
}

type seededRotator struct {
	fakeRotator
	meta corecredential.CredentialMeta
}

func (s *seededRotator) CurrentMeta() corecredential.CredentialMeta { return s.meta }

var _ CurrentMetaProvider = (*seededRotator)(nil)
