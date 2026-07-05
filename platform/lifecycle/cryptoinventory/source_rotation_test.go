package cryptoinventory

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/lifecycle/rotation"
	"github.com/snaplink/sso/shared/core/corecredential"
)

const testCredType corecredential.CredentialType = "test_cred"

// fakeRotator is a minimal corecredential.CredentialRotator +
// CompromiseRotator + CurrentMetaProvider test double, mirroring the
// rotation package's own fakeCompromiseRotator test fixture (this package
// cannot import infrastructure/defaultimpl's real RotatingJWEDecrypter
// without risking an import cycle back through interfaces/sso, which is
// what wires this package's Sources together).
type fakeRotator struct {
	credType        corecredential.CredentialType
	version         int
	compromiseCalls int
}

func (f *fakeRotator) Type() corecredential.CredentialType {
	if f.credType == "" {
		return testCredType
	}
	return f.credType
}
func (f *fakeRotator) OverlapWindow() time.Duration { return time.Minute }

func (f *fakeRotator) Rotate(context.Context) (corecredential.CredentialMeta, error) {
	f.version++
	return f.metaAt(f.version), nil
}

func (f *fakeRotator) RotateCompromised(context.Context) (corecredential.CredentialMeta, error) {
	f.compromiseCalls++
	f.version++
	return f.metaAt(f.version), nil
}

func (f *fakeRotator) CurrentMeta() corecredential.CredentialMeta { return f.metaAt(f.version) }

func (f *fakeRotator) metaAt(v int) corecredential.CredentialMeta {
	return corecredential.CredentialMeta{
		ID:        string(f.Type()) + "/v" + strconv.Itoa(v),
		Type:      f.Type(),
		Version:   v,
		Status:    corecredential.CredentialStatusActive,
		Algorithm: "HMAC-SHA256",
	}
}

var _ corecredential.CompromiseRotator = (*fakeRotator)(nil)
var _ rotation.CurrentMetaProvider = (*fakeRotator)(nil)

func TestRotationSource_Keys(t *testing.T) {
	reg := rotation.NewRegistry()
	rot := &fakeRotator{version: 1}
	if err := reg.Register(rot, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	src := &RotationSource{Registry: reg}

	entries, err := src.Keys(context.Background())
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Keys() = %+v, want 1 entry", entries)
	}
	e := entries[0]
	if e.KeyID != "test_cred/v1" || e.Algorithm != "HMAC-SHA256" || e.Purpose != PurposeSign || e.Status != StatusActive {
		t.Errorf("entry = %+v", e)
	}
}

func TestRotationSource_Keys_JWEDecryptionIsEncryptPurpose(t *testing.T) {
	reg := rotation.NewRegistry()
	rot := &fakeRotator{credType: corecredential.CredentialTypeJWEDecryption, version: 1}
	if err := reg.Register(rot, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	src := &RotationSource{Registry: reg}

	entries, err := src.Keys(context.Background())
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(entries) != 1 || entries[0].Purpose != PurposeEncrypt {
		t.Fatalf("entries = %+v, want 1 entry with Purpose encrypt", entries)
	}
}

func TestRotationSource_Keys_NilRegistry(t *testing.T) {
	src := &RotationSource{}
	entries, err := src.Keys(context.Background())
	if err != nil || entries != nil {
		t.Fatalf("Keys() = %v, %v; want nil, nil for an unset Registry", entries, err)
	}
}

func TestRotationSource_RetireKey_TriggersSchedulerCompromise(t *testing.T) {
	reg := rotation.NewRegistry()
	rot := &fakeRotator{version: 1}
	if err := reg.Register(rot, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sched := rotation.NewScheduler(reg)
	src := &RotationSource{Registry: reg, Scheduler: sched}

	// RetireKey maps a keyID back to its CredentialType using the mapping
	// built by the most recent Keys() call, so pull once first — exactly
	// how MemoryInventory.locate uses a Source in practice.
	if _, err := src.Keys(context.Background()); err != nil {
		t.Fatalf("Keys: %v", err)
	}

	if err := src.RetireKey(context.Background(), "test_cred/v1"); err != nil {
		t.Fatalf("RetireKey: %v", err)
	}
	if rot.compromiseCalls != 1 {
		t.Errorf("compromiseCalls = %d, want 1", rot.compromiseCalls)
	}
}

func TestRotationSource_RetireKey_NilSchedulerIsNoop(t *testing.T) {
	reg := rotation.NewRegistry()
	rot := &fakeRotator{version: 1}
	if err := reg.Register(rot, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	src := &RotationSource{Registry: reg} // no Scheduler

	if _, err := src.Keys(context.Background()); err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if err := src.RetireKey(context.Background(), "test_cred/v1"); err != nil {
		t.Fatalf("RetireKey with nil Scheduler should be a no-op, got err: %v", err)
	}
	if rot.compromiseCalls != 0 {
		t.Errorf("compromiseCalls = %d, want 0 (no Scheduler wired)", rot.compromiseCalls)
	}
}

func TestRotationSource_RetireKey_UnknownKeyIsNoop(t *testing.T) {
	reg := rotation.NewRegistry()
	sched := rotation.NewScheduler(reg)
	src := &RotationSource{Registry: reg, Scheduler: sched}

	if err := src.RetireKey(context.Background(), "never-seen"); err != nil {
		t.Fatalf("RetireKey for an unknown keyID should be a no-op, got err: %v", err)
	}
}
