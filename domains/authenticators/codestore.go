package authenticators

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/snaplink/sso/shared/spi"
)

// ErrCodeInvalid is returned when a verification code does not match or has expired.
var ErrCodeInvalid = errors.New("authenticators: code invalid or expired")

// DefaultCodeResendCooldown is the minimum interval between OTP sends to the
// same target. Prevents amplification attacks via repeated /send-code calls.
const DefaultCodeResendCooldown = 60 * time.Second

// CodeStore stores short-lived one-time verification codes (SMS / email / magic link).
// Save persists a (key, code) pair with a TTL. Verify performs a constant-time
// comparison and consumes the code on success.
type CodeStore interface {
	Save(ctx context.Context, key, code string, ttl time.Duration) error
	Verify(ctx context.Context, key, code string) error
}

// MemoryCodeStore is a process-local CodeStore. Use Redis or a database in production.
type MemoryCodeStore struct {
	mu       sync.Mutex
	entries  map[string]codeEntry
	cooldown time.Duration
}

type codeEntry struct {
	code      string
	expiresAt time.Time
	savedAt   time.Time
}

func NewMemoryCodeStore() *MemoryCodeStore {
	return &MemoryCodeStore{
		entries:  make(map[string]codeEntry),
		cooldown: DefaultCodeResendCooldown,
	}
}

// NewMemoryCodeStoreWithCooldown creates a MemoryCodeStore with a custom cooldown.
// Pass 0 to disable cooldown enforcement (for tests and single-use scenarios).
func NewMemoryCodeStoreWithCooldown(cooldown time.Duration) *MemoryCodeStore {
	return &MemoryCodeStore{
		entries:  make(map[string]codeEntry),
		cooldown: cooldown,
	}
}

func (m *MemoryCodeStore) Save(_ context.Context, key, code string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cooldown > 0 {
		if e, ok := m.entries[key]; ok && time.Since(e.savedAt) < m.cooldown {
			return spi.ErrCodeCooldownActive
		}
	}
	m.entries[key] = codeEntry{code: code, expiresAt: time.Now().Add(ttl), savedAt: time.Now()}
	return nil
}

func (m *MemoryCodeStore) Verify(_ context.Context, key, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		delete(m.entries, key)
		return ErrCodeInvalid
	}
	if subtle.ConstantTimeCompare([]byte(e.code), []byte(code)) != 1 {
		return ErrCodeInvalid
	}
	delete(m.entries, key)
	return nil
}

// GenerateNumericCode returns a cryptographically random decimal string of length n.
func GenerateNumericCode(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("authenticators: code length must be positive")
	}
	out := make([]byte, n)
	max := big.NewInt(int64(len(numericDigits)))
	for i := range n {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = numericDigits[idx.Int64()]
	}
	return string(out), nil
}
