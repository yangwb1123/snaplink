package memorystoreoauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memreaper"
	"github.com/snaplink/sso/protocols/oauth"
)

// userCodeAlphabet is base32 minus easily-confused glyphs (0/O, 1/I/L).
// 8 chars from this set = 32^8 ≈ 1.1 trillion combinations, enough for
// a meaningful brute-force defense given the short TTL + per-poll
// interval throttling.
const userCodeAlphabet = "BCDFGHJKMNPQRSTVWXYZ23456789"

// MemoryDeviceCodeStore is an in-process oauth.DeviceCodeStore for
// single-replica deployments. Multi-replica fleets need a shared
// backend (Redis / SQL) so a code issued on replica A is approvable
// on replica B and pollable on replica C.
//
// MaxEntries (0 = unbounded, the default) and StartReaper are optional:
// an expired code is only ever detected + deleted when a caller happens
// to look up its exact device_code/user_code again (GetBy*/Approve/
// Deny/ConsumeIfApproved); a code the end user never finishes polling or
// approving has no such caller and would otherwise sit in both maps
// forever. Neither changes behavior unless explicitly configured.
type MemoryDeviceCodeStore struct {
	MaxEntries int

	mu           sync.Mutex
	byDeviceCode map[string]*oauth.DeviceCode
	byUserCode   map[string]*oauth.DeviceCode
	reaper       *memreaper.Reaper
}

func NewMemoryDeviceCodeStore() *MemoryDeviceCodeStore {
	return &MemoryDeviceCodeStore{
		byDeviceCode: make(map[string]*oauth.DeviceCode),
		byUserCode:   make(map[string]*oauth.DeviceCode),
	}
}

// StartReaper launches a background sweep of expired, never-completed
// device codes every interval. A non-positive interval is a no-op.
// Idempotent — calling it again stops the previous reaper first.
func (m *MemoryDeviceCodeStore) StartReaper(interval time.Duration) {
	_ = m.reaper.Close()
	m.reaper = memreaper.Start(interval, m.sweepExpired)
}

// Close stops the background reaper started via StartReaper, if any.
func (m *MemoryDeviceCodeStore) Close() error {
	return m.reaper.Close()
}

func (m *MemoryDeviceCodeStore) sweepExpired(time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for code, entry := range m.byDeviceCode {
		if entry.IsExpired() {
			delete(m.byDeviceCode, code)
			delete(m.byUserCode, entry.UserCode)
		}
	}
}

func (m *MemoryDeviceCodeStore) Issue(_ context.Context, dc *oauth.DeviceCode) error {
	if dc == nil || dc.DeviceCode == "" || dc.UserCode == "" {
		return oauth.ErrDeviceCodeNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.MaxEntries > 0 {
		if _, exists := m.byDeviceCode[dc.DeviceCode]; !exists && len(m.byDeviceCode) >= m.MaxEntries {
			return ErrStoreAtCapacity
		}
	}
	scopes := append([]string(nil), dc.Scopes...)
	attrs := copyMap(dc.Attributes)
	entry := &oauth.DeviceCode{
		DeviceCode: dc.DeviceCode,
		UserCode:   dc.UserCode,
		ClientID:   dc.ClientID,
		Scopes:     scopes,
		Nonce:      dc.Nonce,
		UserID:     dc.UserID,
		Provider:   dc.Provider,
		Attributes: attrs,
		Approved:   dc.Approved,
		Denied:     dc.Denied,
		LastPoll:   dc.LastPoll,
		Interval:   dc.Interval,
		// Resources carry the RFC 8707 audience restriction — must persist
		// through Approve/Consume or the minted token's audience is widened.
		Resources: append([]string(nil), dc.Resources...),
		ExpiresAt: dc.ExpiresAt,
	}
	m.byDeviceCode[dc.DeviceCode] = entry
	m.byUserCode[dc.UserCode] = entry
	return nil
}

func (m *MemoryDeviceCodeStore) GetByDeviceCode(_ context.Context, deviceCode string) (*oauth.DeviceCode, error) {
	m.mu.Lock()
	entry, ok := m.byDeviceCode[deviceCode]
	if !ok || entry.IsExpired() {
		m.mu.Unlock()
		return nil, oauth.ErrDeviceCodeNotFound
	}
	cp := copyDeviceCode(entry)
	m.mu.Unlock()
	return cp, nil
}

func (m *MemoryDeviceCodeStore) GetByUserCode(_ context.Context, userCode string) (*oauth.DeviceCode, error) {
	m.mu.Lock()
	entry, ok := m.byUserCode[userCode]
	if !ok || entry.IsExpired() {
		m.mu.Unlock()
		return nil, oauth.ErrDeviceCodeNotFound
	}
	cp := copyDeviceCode(entry)
	m.mu.Unlock()
	return cp, nil
}

// copyDeviceCode returns an independent snapshot of entry so callers
// never alias the live map value that Approve/Deny/UpdateLastPoll mutate
// in place under lock — without this, the device /token poll's unlocked
// read of dc.Approved/UserID/Provider/Attributes races those writers.
// Mirrors MemoryCIBAStore.Get's defensive-copy idiom.
func copyDeviceCode(entry *oauth.DeviceCode) *oauth.DeviceCode {
	cp := *entry
	cp.Scopes = append([]string(nil), entry.Scopes...)
	cp.Resources = append([]string(nil), entry.Resources...)
	cp.Attributes = copyMap(entry.Attributes)
	return &cp
}

func (m *MemoryDeviceCodeStore) Approve(_ context.Context, userCode, userID, provider string, attributes map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.byUserCode[userCode]
	if !ok || entry.IsExpired() {
		return oauth.ErrDeviceCodeNotFound
	}
	entry.Approved = true
	entry.UserID = userID
	entry.Provider = provider
	entry.Attributes = copyMap(attributes)
	return nil
}

func (m *MemoryDeviceCodeStore) Deny(_ context.Context, userCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.byUserCode[userCode]
	if !ok || entry.IsExpired() {
		return oauth.ErrDeviceCodeNotFound
	}
	entry.Denied = true
	return nil
}

func (m *MemoryDeviceCodeStore) UpdateLastPoll(_ context.Context, deviceCode string, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.byDeviceCode[deviceCode]
	if !ok {
		return oauth.ErrDeviceCodeNotFound
	}
	entry.LastPoll = t
	return nil
}

func (m *MemoryDeviceCodeStore) Delete(_ context.Context, deviceCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.byDeviceCode[deviceCode]
	if !ok {
		return nil // idempotent
	}
	delete(m.byDeviceCode, deviceCode)
	delete(m.byUserCode, entry.UserCode)
	return nil
}

// ConsumeIfApproved atomically (under the store mutex) returns + deletes the
// code iff it is approved; a pending/denied/unknown/expired code returns
// ErrDeviceCodeNotFound WITHOUT consuming. So of N concurrent callers exactly
// one wins, which is the single-use claim the token exchange makes before
// minting (avoids two token sets from one approved code).
func (m *MemoryDeviceCodeStore) ConsumeIfApproved(_ context.Context, deviceCode string) (*oauth.DeviceCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.byDeviceCode[deviceCode]
	if !ok || entry.IsExpired() || !entry.Approved {
		return nil, oauth.ErrDeviceCodeNotFound
	}
	cp := copyDeviceCode(entry)
	delete(m.byDeviceCode, deviceCode)
	delete(m.byUserCode, entry.UserCode)
	return cp, nil
}

// GenerateDeviceCode mints a 32-byte base64url device_code suitable
// for backchannel polling. Long + opaque — the device prints it to
// logs in some operator setups.
func GenerateDeviceCode() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateUserCode mints an 8-char base32-no-ambiguous user_code in
// the form XXXX-XXXX. Short + readable so users can transcribe it
// reliably from a TV screen onto a phone. Dash is purely cosmetic;
// servers MUST accept the code with or without it (callers should
// strip on input).
func GenerateUserCode() (string, error) {
	const length = 8
	out := make([]byte, length)
	for i := range length {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeAlphabet))))
		if err != nil {
			return "", err
		}
		out[i] = userCodeAlphabet[n.Int64()]
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}

// Compile-time checks.
var (
	_ oauth.DeviceCodeStore = (*MemoryDeviceCodeStore)(nil)
	_ io.Closer             = (*MemoryDeviceCodeStore)(nil)
)
