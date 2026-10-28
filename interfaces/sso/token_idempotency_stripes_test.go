package sso

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
)

func TestTokenIdempotencyStripesFixedStableAndInstanceLocal(t *testing.T) {
	first, second := &Server{}, &Server{}
	if len(first.idempotentStripes) != 256 {
		t.Fatal("coordination must remain a fixed 256-slot array")
	}
	seen := make(map[*sync.Mutex]bool)
	for n := range 65536 {
		key := fmt.Sprintf("token:bounded-test-%d", n)
		index := sha256.Sum256([]byte(key))[0]
		mu := first.tokenIdempotencyMutex(key)
		if mu != &first.idempotentStripes[index] || mu != first.tokenIdempotencyMutex(key) {
			t.Fatal("complete-key SHA256 selection is not stable")
		}
		if mu == second.tokenIdempotencyMutex(key) {
			t.Fatal("different Server instances shared lock objects")
		}
		seen[mu] = true
	}
	if len(seen) != 256 {
		t.Fatalf("bounded input inventory reached %d lock objects, want exactly 256", len(seen))
	}
	key := "token:instance-isolation"
	first.tokenIdempotencyMutex(key).Lock()
	defer first.tokenIdempotencyMutex(key).Unlock()
	peer := second.tokenIdempotencyMutex(key)
	if !peer.TryLock() {
		t.Fatal("one instance's lock blocked another instance")
	}
	peer.Unlock()
}

func TestTokenIdempotencyStripesCollisionSharesOnlyLock(t *testing.T) {
	server := &Server{}
	first := "token:collision-first"
	mu := server.tokenIdempotencyMutex(first)
	for n := range 65536 {
		other := fmt.Sprintf("token:collision-second-%d", n)
		if server.tokenIdempotencyMutex(other) != mu {
			continue
		}
		mu.Lock()
		if server.tokenIdempotencyMutex(other).TryLock() {
			mu.Unlock()
			server.tokenIdempotencyMutex(other).Unlock()
			t.Fatal("colliding keys did not select the same mutex")
		}
		mu.Unlock()
		return
	}
	t.Fatal("bounded collision search exhausted")
}
