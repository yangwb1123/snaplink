package federation

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryHistoricalKeyStore_RecordAndList(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryHistoricalKeyStore()

	now := time.Now()
	keys := []*HistoricalKey{
		{KID: "key-1", ActiveFrom: now.Add(-48 * time.Hour), ActiveUntil: now.Add(-24 * time.Hour)},
		{KID: "key-2", ActiveFrom: now.Add(-24 * time.Hour), ActiveUntil: now},
		{KID: "key-3", ActiveFrom: now, ActiveUntil: now.Add(24 * time.Hour)},
	}

	for _, k := range keys {
		if err := store.RecordKey(ctx, k); err != nil {
			t.Fatalf("RecordKey(%s): %v", k.KID, err)
		}
	}

	listed, err := store.HistoricalKeys(ctx)
	if err != nil {
		t.Fatalf("HistoricalKeys: %v", err)
	}
	if len(listed) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(listed))
	}

	// Most recent first
	if listed[0].KID != "key-3" {
		t.Errorf("expected most recent first: key-3, got %s", listed[0].KID)
	}
}

func TestMemoryHistoricalKeyStore_GetByKID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryHistoricalKeyStore()

	now := time.Now()
	_ = store.RecordKey(ctx, &HistoricalKey{KID: "find-me", ActiveFrom: now, JWK: map[string]any{"kty": "EC", "crv": "P-256"}})

	got, err := store.HistoricalKeysByKID(ctx, "find-me")
	if err != nil {
		t.Fatalf("HistoricalKeysByKID: %v", err)
	}
	if got.KID != "find-me" {
		t.Errorf("expected kid 'find-me', got '%s'", got.KID)
	}
	if got.JWK["kty"] != "EC" {
		t.Errorf("expected JWK kty 'EC', got '%v'", got.JWK["kty"])
	}
}

func TestMemoryHistoricalKeyStore_GetByKIDNotFound(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryHistoricalKeyStore()

	_, err := store.HistoricalKeysByKID(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestMemoryHistoricalKeyStore_AutoGenerateID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryHistoricalKeyStore()

	k := &HistoricalKey{ActiveFrom: time.Now()}
	if err := store.RecordKey(ctx, k); err != nil {
		t.Fatalf("RecordKey: %v", err)
	}
	if k.KID == "" {
		t.Fatal("KID should be auto-generated")
	}
}

func TestMemoryHistoricalKeyStore_ConcurrentRecord(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryHistoricalKeyStore()

	var wg sync.WaitGroup
	wg.Add(10)

	for i := range 10 {
		go func(n int) {
			defer wg.Done()
			_ = store.RecordKey(ctx, &HistoricalKey{
				KID:        "ck-" + itoa(n),
				ActiveFrom: time.Now(),
			})
		}(i)
	}
	wg.Wait()

	listed, _ := store.HistoricalKeys(ctx)
	if len(listed) != 10 {
		t.Errorf("expected 10 keys, got %d", len(listed))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
