package rotation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core/corecredential"
)

// fakeCompromiseRotator is a corecredential.CompromiseRotator test double: it
// tracks its version, reports affected dependents, and can be scripted to fail
// its emergency rotation. It seeds itself as version 1 (CurrentMetaProvider) so
// Register installs a known active version for Compromise to retire.
type fakeCompromiseRotator struct {
	version         int
	overlap         time.Duration
	deps            []corecredential.Dependency
	compromiseErr   error
	compromiseCalls int
}

func (f *fakeCompromiseRotator) Type() corecredential.CredentialType { return testCredType }
func (f *fakeCompromiseRotator) OverlapWindow() time.Duration        { return f.overlap }

func (f *fakeCompromiseRotator) Rotate(context.Context) (corecredential.CredentialMeta, error) {
	f.version++
	return f.metaAt(f.version), nil
}

func (f *fakeCompromiseRotator) RotateCompromised(context.Context) (corecredential.CredentialMeta, error) {
	f.compromiseCalls++
	if f.compromiseErr != nil {
		return corecredential.CredentialMeta{}, f.compromiseErr
	}
	f.version++
	return f.metaAt(f.version), nil
}

func (f *fakeCompromiseRotator) Dependents() []corecredential.Dependency { return f.deps }
func (f *fakeCompromiseRotator) CurrentMeta() corecredential.CredentialMeta {
	return f.metaAt(f.version)
}
func (f *fakeCompromiseRotator) metaAt(v int) corecredential.CredentialMeta {
	return corecredential.CredentialMeta{
		ID:      fmt.Sprintf("%s/v%d", testCredType, v),
		Type:    testCredType,
		Version: v,
		Status:  corecredential.CredentialStatusActive,
	}
}

var _ corecredential.CompromiseRotator = (*fakeCompromiseRotator)(nil)

// recordingNotifier is a local corecredential.DependentPartyNotifier double —
// kept in-package (like fakeStatusStore) to avoid a test-only import of the
// defaultimpl memory notifier.
type recordingNotifier struct {
	mu      sync.Mutex
	notices []corecredential.RotationNotice
}

func (n *recordingNotifier) Notify(_ context.Context, notice corecredential.RotationNotice) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.notices = append(n.notices, notice)
	return nil
}

func (n *recordingNotifier) all() []corecredential.RotationNotice {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]corecredential.RotationNotice(nil), n.notices...)
}

// TestScheduler_CompromiseRetiresLeakedVersionImmediately is the central Phase-3
// property: an emergency compromise force-rotates to a fresh version AND retires
// the leaked one with NO overlap — the old version is marked compromised (not
// retiring) and drops out of the live inventory at once, unlike a routine
// rotation which parks it in the overlap window.
func TestScheduler_CompromiseRetiresLeakedVersionImmediately(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	// A generous overlap proves the point: even with a long window configured,
	// compromise keeps NONE of it.
	rotator := &fakeCompromiseRotator{version: 1, overlap: time.Hour, deps: []corecredential.Dependency{corecredential.DependencyJWKS}}
	if err := reg.Register(rotator, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	store := newFakeStatusStore()
	notifier := &recordingNotifier{}
	sched, events := newTestScheduler(t, reg, WithStatusStore(store), WithNotifier(notifier))

	res, err := sched.Compromise(context.Background(), testCredType, "kms key leaked")
	if err != nil {
		t.Fatalf("Compromise: %v", err)
	}
	if res.New.Version != 2 || res.Compromised.Version != 1 {
		t.Fatalf("result = new v%d / compromised v%d, want new v2 / compromised v1", res.New.Version, res.Compromised.Version)
	}

	// Inventory: only the fresh v2 active — the leaked v1 is gone, and there is
	// NO retiring slot (the emergency path keeps no overlap).
	inv := sched.Inventory()
	if len(inv) != 1 || inv[0].Version != 2 || inv[0].Status != corecredential.CredentialStatusActive {
		t.Fatalf("Inventory() after compromise = %+v, want only active v2", inv)
	}

	// Status store: the leaked version is recorded compromised, the new one active.
	if got := store.status(testCredType, fmt.Sprintf("%s/v1", testCredType)); got != corecredential.CredentialStatusCompromised {
		t.Fatalf("v1 store status = %q, want compromised", got)
	}
	if got := store.status(testCredType, fmt.Sprintf("%s/v2", testCredType)); got != corecredential.CredentialStatusActive {
		t.Fatalf("v2 store status = %q, want active", got)
	}
	waitForEvent(t, events, EventCompromised, time.Second)
}

// TestScheduler_CompromiseNotifiesDependentsWithReason proves the notifier fires
// exactly once with Compromised=true, the operator reason, and the credential's
// declared affected-dependent set — the signal a JWKS-changed broadcast rides.
func TestScheduler_CompromiseNotifiesDependentsWithReason(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	rotator := &fakeCompromiseRotator{version: 1, deps: []corecredential.Dependency{corecredential.DependencyJWKS}}
	if err := reg.Register(rotator, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	notifier := &recordingNotifier{}
	sched, _ := newTestScheduler(t, reg, WithNotifier(notifier))

	if _, err := sched.Compromise(context.Background(), testCredType, "incident-4211"); err != nil {
		t.Fatalf("Compromise: %v", err)
	}

	notices := notifier.all()
	if len(notices) != 1 {
		t.Fatalf("notices = %d, want 1", len(notices))
	}
	n := notices[0]
	if !n.Compromised {
		t.Error("notice.Compromised = false, want true")
	}
	if n.Reason != "incident-4211" {
		t.Errorf("notice.Reason = %q, want incident-4211", n.Reason)
	}
	if n.Type != testCredType || n.NewMeta.Version != 2 {
		t.Errorf("notice type/version = %q/v%d, want %q/v2", n.Type, n.NewMeta.Version, testCredType)
	}
	if len(n.Dependents) != 1 || n.Dependents[0] != corecredential.DependencyJWKS {
		t.Errorf("notice.Dependents = %v, want [jwks]", n.Dependents)
	}
}

// TestScheduler_CompromiseUnknownType rejects a class that was never registered.
func TestScheduler_CompromiseUnknownType(t *testing.T) {
	t.Parallel()
	sched, _ := newTestScheduler(t, NewRegistry())
	_, err := sched.Compromise(context.Background(), "never_registered", "x")
	if !errors.Is(err, ErrUnknownCredentialType) {
		t.Fatalf("Compromise(unregistered) = %v, want ErrUnknownCredentialType", err)
	}
}

// TestScheduler_CompromiseUnsupportedRotator refuses a class whose rotator
// cannot instantly retire its secret (implements CredentialRotator but not
// CompromiseRotator) — leaving the leaked secret accepted through an overlap
// would defeat the point, so the framework fails loudly instead.
func TestScheduler_CompromiseUnsupportedRotator(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	if err := reg.Register(&fakeRotator{}, time.Hour); err != nil { // fakeRotator has no RotateCompromised
		t.Fatalf("Register: %v", err)
	}
	sched, _ := newTestScheduler(t, reg)
	_, err := sched.Compromise(context.Background(), testCredType, "x")
	if !errors.Is(err, corecredential.ErrCompromiseUnsupported) {
		t.Fatalf("Compromise(plain rotator) = %v, want ErrCompromiseUnsupported", err)
	}
}

// TestScheduler_CompromiseMintFailureKeepsOldServing proves the safety
// invariant: when minting the replacement fails, the leaked version is NOT
// dropped — the old credential keeps serving so the class never reaches
// zero-usable-credentials, and the operator can retry.
func TestScheduler_CompromiseMintFailureKeepsOldServing(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	boom := errors.New("hsm unreachable")
	rotator := &fakeCompromiseRotator{version: 1, compromiseErr: boom}
	if err := reg.Register(rotator, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sched, _ := newTestScheduler(t, reg)

	if _, err := sched.Compromise(context.Background(), testCredType, "x"); !errors.Is(err, boom) {
		t.Fatalf("Compromise = %v, want wrapped %v", err, boom)
	}
	inv := sched.Inventory()
	if len(inv) != 1 || inv[0].Version != 1 || inv[0].Status != corecredential.CredentialStatusActive {
		t.Fatalf("Inventory() after failed compromise = %+v, want the untouched active v1", inv)
	}
}
