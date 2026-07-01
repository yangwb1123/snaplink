package memorystorecredential

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	"github.com/snaplink/sso/shared/core"
)

// MemoryRecoveryCodeStore is an in-process, non-persistent recovery
// code store using SHA-256 hashes. Suitable for single-replica dev
// and test; production deployments should use the SQLite or Redis
// peer.
type MemoryRecoveryCodeStore struct {
	mu        sync.RWMutex
	userCodes map[string]map[string]struct{} // userID → hash → consumed marker
}

// NewMemoryRecoveryCodeStore returns an empty MemoryRecoveryCodeStore.
func NewMemoryRecoveryCodeStore() *MemoryRecoveryCodeStore {
	return &MemoryRecoveryCodeStore{
		userCodes: make(map[string]map[string]struct{}),
	}
}

// Generate produces n random recovery codes, stores their SHA-256
// hashes, and returns the plaintext codes.
func (s *MemoryRecoveryCodeStore) Generate(_ context.Context, userID string, n int) ([]string, error) {
	if n <= 0 || n > 20 {
		n = core.DefaultRecoveryCodeCount
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.userCodes[userID]; !ok {
		s.userCodes[userID] = make(map[string]struct{})
	}

	codes := make([]string, n)
	for i := range n {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("recovery code generation: %w", err)
		}
		hash := hashRecoveryCode(code)
		s.userCodes[userID][hash] = struct{}{}
		codes[i] = code
	}
	return codes, nil
}

// Consume checks the code hash against stored hashes. Returns true
// when valid and not yet consumed (the code is marked consumed).
func (s *MemoryRecoveryCodeStore) Consume(_ context.Context, userID, code string) (bool, error) {
	hash := hashRecoveryCode(code)
	s.mu.Lock()
	defer s.mu.Unlock()

	codes, ok := s.userCodes[userID]
	if !ok {
		return false, nil
	}
	if _, exists := codes[hash]; !exists {
		return false, nil
	}
	// Mark consumed by deleting the hash.
	delete(codes, hash)
	return true, nil
}

// CountRemaining returns the number of unused codes for the user.
func (s *MemoryRecoveryCodeStore) CountRemaining(_ context.Context, userID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	codes, ok := s.userCodes[userID]
	if !ok {
		return 0, nil
	}
	return len(codes), nil
}

// RevokeAll deletes all stored code hashes for the user.
func (s *MemoryRecoveryCodeStore) RevokeAll(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.userCodes, userID)
	return nil
}

// newRecoveryCode generates a single human-friendly recovery code:
// 16 bytes encoded as 32 hex chars (or custom alphabet). Uses the
// crockford-like alphabet (no I/O/0/1) in groups of 4 for readability.
func newRecoveryCode() (string, error) {
	alphabet := []rune(core.RecoveryCodeAlphabet)
	alphabetLen := big.NewInt(int64(len(alphabet)))
	code := make([]rune, 8) // 8 chars from 32-char alphabet = 40 bits
	for i := range code {
		n, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return "", err
		}
		code[i] = alphabet[n.Int64()]
	}
	return string(code), nil
}

// hashRecoveryCode returns the SHA-256 hex digest of code.
func hashRecoveryCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// compile-time check.
var _ core.RecoveryCodeStore = (*MemoryRecoveryCodeStore)(nil)
