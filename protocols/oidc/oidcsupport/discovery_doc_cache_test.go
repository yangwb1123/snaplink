package oidcsupport

import (
	"strings"
	"testing"
	"time"
)

func TestBuildDocEntry(t *testing.T) {
	t.Parallel()

	body := []byte(`{"issuer":"https://example.com"}`)
	ttl := 5 * time.Second

	entry := BuildDocEntry(body, ttl)
	if entry == nil {
		t.Fatal("BuildDocEntry returned nil")
	}

	// Body preserved
	if string(entry.Body) != string(body) {
		t.Errorf("BuildDocEntry body = %q, want %q", entry.Body, body)
	}

	// ETag is a quoted base64 string
	if !strings.HasPrefix(entry.ETag, `"`) || !strings.HasSuffix(entry.ETag, `"`) {
		t.Errorf("ETag %q should be quoted", entry.ETag)
	}
	if len(entry.ETag) < 10 {
		t.Errorf("ETag %q too short (len=%d)", entry.ETag, len(entry.ETag))
	}

	// ExpiresAt is in the future
	if !time.Now().Before(entry.ExpiresAt) {
		t.Error("ExpiresAt should be in the future")
	}
	// But close to now+ttl
	expected := time.Now().Add(ttl)
	if entry.ExpiresAt.Sub(expected) > time.Second {
		t.Errorf("ExpiresAt = %v, expected ~%v (diff=%v)", entry.ExpiresAt, expected, entry.ExpiresAt.Sub(expected))
	}
}

func TestBuildDocEntryEmptyBody(t *testing.T) {
	t.Parallel()

	entry := BuildDocEntry([]byte{}, time.Second)
	if entry == nil {
		t.Fatal("BuildDocEntry(nil) returned nil")
	}
	if len(entry.Body) != 0 {
		t.Errorf("expected empty body, got %d bytes", len(entry.Body))
	}
}

func TestDocEntryFresh(t *testing.T) {
	t.Parallel()

	// Fresh entry
	entry := BuildDocEntry([]byte(`{"a":1}`), time.Hour)
	if !entry.Fresh() {
		t.Error("expected Fresh() = true for new entry with 1h TTL")
	}

	// Expired entry
	entry.ExpiresAt = time.Now().Add(-time.Second)
	if entry.Fresh() {
		t.Error("expected Fresh() = false for expired entry")
	}

	// Nil entry
	var nilEntry *DocEntry
	if nilEntry.Fresh() {
		t.Error("expected Fresh() = false for nil entry")
	}
}

func TestBuildDocEntryZeroTTL(t *testing.T) {
	t.Parallel()

	entry := BuildDocEntry([]byte(`{"a":1}`), 0)
	if entry.Fresh() {
		t.Error("expected Fresh() = false for zero-TTL entry (already expired)")
	}
}

func TestBuildDocEntryStableETag(t *testing.T) {
	t.Parallel()

	body := []byte(`{"key":"value"}`)
	e1 := BuildDocEntry(body, time.Second)
	e2 := BuildDocEntry(body, time.Hour)

	// Same body produces same ETag regardless of TTL
	if e1.ETag != e2.ETag {
		t.Errorf("ETag should be body-dependent, got %q vs %q", e1.ETag, e2.ETag)
	}
}

func TestBuildDocEntryDifferentBodyDifferentETag(t *testing.T) {
	t.Parallel()

	e1 := BuildDocEntry([]byte(`{"a":1}`), time.Second)
	e2 := BuildDocEntry([]byte(`{"b":2}`), time.Second)

	if e1.ETag == e2.ETag {
		t.Error("ETags for different bodies should differ")
	}
}
