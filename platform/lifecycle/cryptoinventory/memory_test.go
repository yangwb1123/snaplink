package cryptoinventory

import (
	"context"
	"errors"
	"testing"
)

// fakeSource is a minimal, real (non-mock) Source test double: a fixed
// entry list plus an optional retire callback and an optional forced error,
// so tests can exercise every ListKeys/ReportKeyCompromise branch without a
// mocking framework.
type fakeSource struct {
	name        string
	entries     []Entry
	err         error
	retireCalls []string
	retireErr   error
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Keys(context.Context) ([]Entry, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.entries, nil
}

func (f *fakeSource) RetireKey(_ context.Context, keyID string) error {
	f.retireCalls = append(f.retireCalls, keyID)
	return f.retireErr
}

var _ Source = (*fakeSource)(nil)
var _ Retirer = (*fakeSource)(nil)

// fakeReadOnlySource is a Source that does NOT implement Retirer, exercising
// ReportKeyCompromise's "no retirer available" path.
type fakeReadOnlySource struct {
	name    string
	entries []Entry
}

func (f *fakeReadOnlySource) Name() string { return f.name }
func (f *fakeReadOnlySource) Keys(context.Context) ([]Entry, error) {
	return f.entries, nil
}

var _ Source = (*fakeReadOnlySource)(nil)

func TestMemoryInventory_ListKeys(t *testing.T) {
	signing := &fakeSource{name: "signingkeys", entries: []Entry{
		{KeyID: "kid-1", Algorithm: "EdDSA", Purpose: PurposeSign, Status: StatusActive, Source: "signingkeys"},
		{KeyID: "kid-2", Algorithm: "RS256", Purpose: PurposeSign, Status: StatusActive, Source: "signingkeys"},
	}}
	jwe := &fakeReadOnlySource{name: "rotation", entries: []Entry{
		{KeyID: "jwe-enc/v1", Algorithm: "RSA-OAEP-256", Purpose: PurposeEncrypt, Status: StatusActive, Source: "rotation"},
	}}
	broken := &fakeSource{name: "broken", err: errors.New("unreachable")}

	inv := NewMemoryInventory(signing, jwe, broken)

	all, err := inv.ListKeys(context.Background(), Filter{})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	// broken source is skipped (fail-open), not surfaced as an error.
	if len(all) != 3 {
		t.Fatalf("ListKeys() returned %d entries, want 3 (broken source skipped): %+v", len(all), all)
	}

	encOnly, err := inv.ListKeys(context.Background(), Filter{Purpose: PurposeEncrypt})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(encOnly) != 1 || encOnly[0].KeyID != "jwe-enc/v1" {
		t.Fatalf("ListKeys(encrypt) = %+v, want just jwe-enc/v1", encOnly)
	}
}

func TestMemoryInventory_ReportKeyCompromise_TriggersRetirer(t *testing.T) {
	signing := &fakeSource{name: "signingkeys", entries: []Entry{
		{KeyID: "kid-1", Algorithm: "EdDSA", Purpose: PurposeSign, Status: StatusActive, Source: "signingkeys"},
	}}
	inv := NewMemoryInventory(signing)

	entry, err := inv.ReportKeyCompromise(context.Background(), "kid-1", "leaked in incident INC-1")
	if err != nil {
		t.Fatalf("ReportKeyCompromise: %v", err)
	}
	if entry.Status != StatusCompromised {
		t.Errorf("Status = %q, want compromised", entry.Status)
	}
	if entry.CompromiseReason != "leaked in incident INC-1" {
		t.Errorf("CompromiseReason = %q", entry.CompromiseReason)
	}
	if len(signing.retireCalls) != 1 || signing.retireCalls[0] != "kid-1" {
		t.Errorf("retireCalls = %v, want [kid-1]", signing.retireCalls)
	}

	// The overlay persists on subsequent ListKeys calls even though the
	// underlying Source keeps reporting the key as active — the source
	// truthfully doesn't know about compromise bookkeeping, this package does.
	keys, err := inv.ListKeys(context.Background(), Filter{})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Status != StatusCompromised {
		t.Fatalf("ListKeys after compromise = %+v, want compromised overlay applied", keys)
	}
}

func TestMemoryInventory_ReportKeyCompromise_NoRetirerStillRecords(t *testing.T) {
	jwe := &fakeReadOnlySource{name: "rotation", entries: []Entry{
		{KeyID: "jwe-enc/v1", Algorithm: "RSA-OAEP-256", Purpose: PurposeEncrypt, Status: StatusActive, Source: "rotation"},
	}}
	inv := NewMemoryInventory(jwe)

	entry, err := inv.ReportKeyCompromise(context.Background(), "jwe-enc/v1", "no retirer wired")
	if err != nil {
		t.Fatalf("ReportKeyCompromise: %v", err)
	}
	if entry.Status != StatusCompromised {
		t.Errorf("Status = %q, want compromised even without a Retirer", entry.Status)
	}
}

func TestMemoryInventory_ReportKeyCompromise_UnknownKeyErrors(t *testing.T) {
	inv := NewMemoryInventory(&fakeSource{name: "signingkeys"})

	_, err := inv.ReportKeyCompromise(context.Background(), "does-not-exist", "reason")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
}
