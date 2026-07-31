package cryptoinventory

import (
	"context"
	"errors"
	"testing"
)

func TestStaticSource_Keys_DefaultsSource(t *testing.T) {
	src := &StaticSource{
		SourceName: "kms",
		Entries: []Entry{
			{KeyID: "arn:aws:kms:...:key/abc", Algorithm: "ECDSA_SHA_256", Purpose: PurposeSign, Status: StatusActive, BackingStore: "kms:awskms"},
			{KeyID: "custom", Source: "already-set"},
		},
	}

	entries, err := src.Keys(context.Background())
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Keys() = %+v, want 2 entries", entries)
	}
	if entries[0].Source != "kms" {
		t.Errorf("entries[0].Source = %q, want defaulted to SourceName", entries[0].Source)
	}
	if entries[1].Source != "already-set" {
		t.Errorf("entries[1].Source = %q, want preserved as-is", entries[1].Source)
	}
	if src.Name() != "kms" {
		t.Errorf("Name() = %q, want kms", src.Name())
	}
}

func TestStaticSource_RetireKey(t *testing.T) {
	var retiredWith string
	src := &StaticSource{
		SourceName: "mtls_trust_anchors",
		OnRetire: func(_ context.Context, keyID string) error {
			retiredWith = keyID
			return nil
		},
	}
	if err := src.RetireKey(context.Background(), "anchor-1"); err != nil {
		t.Fatalf("RetireKey: %v", err)
	}
	if retiredWith != "anchor-1" {
		t.Errorf("OnRetire called with %q, want anchor-1", retiredWith)
	}

	// Nil OnRetire is reported exactly as unsupported.
	readOnly := &StaticSource{SourceName: "kms"}
	if err := readOnly.RetireKey(context.Background(), "anchor-1"); !errors.Is(err, ErrRetirementUnsupported) {
		t.Errorf("RetireKey with nil OnRetire = %v, want unsupported", err)
	}

	// A propagated OnRetire error surfaces to the caller.
	boom := errors.New("boom")
	failing := &StaticSource{SourceName: "kms", OnRetire: func(context.Context, string) error { return boom }}
	if err := failing.RetireKey(context.Background(), "x"); !errors.Is(err, boom) {
		t.Errorf("RetireKey err = %v, want %v", err, boom)
	}
}
