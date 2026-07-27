package memorystorecredential

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
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

// trustedDeviceRecord is the server-side representation of one grant: the
// public core.TrustedDevice metadata plus the token's hash. The plaintext
// token is NEVER stored — only returned once, at Trust time.
type trustedDeviceRecord struct {
	device core.TrustedDevice
	hash   string
}

// MemoryTrustedDeviceStore is an in-process, non-persistent
// core.TrustedDeviceStore. Suitable for single-replica dev/test;
// production deployments needing MFA-skip grants to survive a restart (or
// be visible across replicas) should use the SQLite or a shared-backend
// peer.
//
// Records are keyed first by userID so every operation this store performs
// (Verify, ListByUser, Revoke, RevokeAll) is inherently scoped to that
// user's own slice — a cross-user leak or cross-user revoke is structurally
// impossible rather than merely checked, the same discipline
// MemoryMFAEnrollmentStore uses for RemoveFactor.
type MemoryTrustedDeviceStore struct {
	mu      sync.Mutex
	devices map[string]map[string]*trustedDeviceRecord // userID -> deviceID -> record
}

// NewMemoryTrustedDeviceStore returns an empty MemoryTrustedDeviceStore.
func NewMemoryTrustedDeviceStore() *MemoryTrustedDeviceStore {
	return &MemoryTrustedDeviceStore{devices: make(map[string]map[string]*trustedDeviceRecord)}
}

func (m *MemoryTrustedDeviceStore) Trust(_ context.Context, userID, clientID, label string, ttl time.Duration) (string, *core.TrustedDevice, error) {
	if userID == "" {
		return "", nil, fmt.Errorf("memorystorecredential: trust: empty user id")
	}
	if ttl <= 0 {
		ttl = core.DefaultTrustedDeviceTTL
	}
	token, err := newTrustedDeviceToken()
	if err != nil {
		return "", nil, fmt.Errorf("memorystorecredential: generate device token: %w", err)
	}
	id, err := newTrustedDeviceID()
	if err != nil {
		return "", nil, fmt.Errorf("memorystorecredential: generate device id: %w", err)
	}

	now := time.Now()
	dev := core.TrustedDevice{
		ID:        id,
		UserID:    userID,
		ClientID:  clientID,
		Label:     label,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	m.mu.Lock()
	if m.devices[userID] == nil {
		m.devices[userID] = make(map[string]*trustedDeviceRecord)
	}
	m.devices[userID][id] = &trustedDeviceRecord{device: dev, hash: hashTrustedDeviceToken(token)}
	m.mu.Unlock()

	return token, &dev, nil
}

// Verify scans only userID's own records (never another user's), so a
// hash collision across users is not even reachable, let alone a leak.
// Lazily prunes an expired match rather than requiring a sweeper goroutine
// — the same discipline oauth.RefreshTokenStore.Inspect uses.
func (m *MemoryTrustedDeviceStore) Verify(_ context.Context, userID, clientID, token string) (bool, error) {
	if userID == "" || token == "" {
		return false, nil
	}
	hash := hashTrustedDeviceToken(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	recs := m.devices[userID]
	for id, r := range recs {
		if r.hash != hash {
			continue
		}
		if time.Now().After(r.device.ExpiresAt) {
			delete(recs, id)
			return false, nil
		}
		if r.device.ClientID != clientID {
			// Right token, wrong client: the grant exists but does not
			// cover this login — same "no" as an unknown token to the caller.
			return false, nil
		}
		r.device.LastUsedAt = time.Now()
		return true, nil
	}
	return false, nil
}

// ListByUser returns metadata copies only — the hash never leaves this file.
func (m *MemoryTrustedDeviceStore) ListByUser(_ context.Context, userID string) ([]core.TrustedDevice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	recs := m.devices[userID]
	out := make([]core.TrustedDevice, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.device)
	}
	return out, nil
}

// Revoke is idempotent and inherently ownership-scoped: it only ever
// touches m.devices[userID], so an id belonging to another user (or no
// user at all) is silently a no-op — mirrors MemoryMFAEnrollmentStore.RemoveFactor.
func (m *MemoryTrustedDeviceStore) Revoke(_ context.Context, userID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	recs := m.devices[userID]
	delete(recs, id)
	if len(recs) == 0 {
		delete(m.devices, userID)
	}
	return nil
}

// RevokeAll removes every grant for userID and returns the count removed —
// called by the self-service password-change handler (account-compromise
// signal) so a stolen "remember this device" grant can't outlive the
// credential it was minted under.
func (m *MemoryTrustedDeviceStore) RevokeAll(_ context.Context, userID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.devices[userID])
	delete(m.devices, userID)
	return n, nil
}

// newTrustedDeviceToken mints a cryptographically random base64url-encoded
// bearer-equivalent MFA-skip token. core.TrustedDeviceTokenBytes (32 bytes /
// 256 bits) matches oauth refresh-token entropy.
func newTrustedDeviceToken() (string, error) {
	buf := make([]byte, core.TrustedDeviceTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// newTrustedDeviceID mints a random opaque record id — distinct from the
// token: it is safe to log or return in a list response, unlike the token.
func newTrustedDeviceID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashTrustedDeviceToken returns the SHA-256 hex digest of token — the only
// form of the token ever persisted, mirroring hashRecoveryCode.
func hashTrustedDeviceToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// compile-time check.
var _ core.TrustedDeviceStore = (*MemoryTrustedDeviceStore)(nil)
