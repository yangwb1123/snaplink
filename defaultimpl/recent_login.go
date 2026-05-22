package defaultimpl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/snaplink/sso"
)

// MemoryRecentLoginStore is the in-process [sso.RecentLoginStore].
// State lives in a per-subject ring-buffer keyed by SubjectID,
// guarded by a single mutex. Suitable for single-replica deploys +
// tests; cluster deploys want the SQLite peer (defaultimpl/sqlite)
// so detectors running on replica A see entries appended by
// replica B.
//
// Bounded memory: per-subject capacity (default 256 entries) caps
// the per-subject buffer; subjects that haven't logged in within
// `idleSubjectTTL` (default 30 days) are dropped on the next
// PruneOlder. Operators with millions of users should size memory
// budget = subjects * 256 * sizeof(LoginEntry) ≈ a few hundred MB.
type MemoryRecentLoginStore struct {
	mu                sync.Mutex
	entries           map[string][]*sso.LoginEntry
	perSubjectMaxSize int
}

// MemoryRecentLoginStoreOption tunes the store at construction.
type MemoryRecentLoginStoreOption func(*MemoryRecentLoginStore)

// WithRecentLoginPerSubjectCap overrides the default per-subject
// ring-buffer cap (256). Lower = stricter memory bound at the cost
// of detector accuracy on burst-prone subjects.
func WithRecentLoginPerSubjectCap(n int) MemoryRecentLoginStoreOption {
	return func(s *MemoryRecentLoginStore) {
		if n > 0 {
			s.perSubjectMaxSize = n
		}
	}
}

// NewMemoryRecentLoginStore returns an empty in-process store.
func NewMemoryRecentLoginStore(opts ...MemoryRecentLoginStoreOption) *MemoryRecentLoginStore {
	s := &MemoryRecentLoginStore{
		entries:           make(map[string][]*sso.LoginEntry),
		perSubjectMaxSize: 256,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Append persists entry. Empty SubjectID → ErrInvalidLoginEntry
// (anonymous failures shouldn't enter the per-subject store).
func (s *MemoryRecentLoginStore) Append(_ context.Context, entry *sso.LoginEntry) error {
	if entry == nil || entry.SubjectID == "" {
		return sso.ErrInvalidLoginEntry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Defensive copy so the caller mutating the entry after Append
	// doesn't reach into the stored buffer.
	cp := *entry
	bucket := s.entries[entry.SubjectID]
	bucket = append(bucket, &cp)
	// Cap the ring — keep the newest perSubjectMaxSize entries.
	if len(bucket) > s.perSubjectMaxSize {
		bucket = bucket[len(bucket)-s.perSubjectMaxSize:]
	}
	s.entries[entry.SubjectID] = bucket
	return nil
}

// Recent returns up to limit most-recent entries newer than since,
// ordered newest-first.
func (s *MemoryRecentLoginStore) Recent(_ context.Context, subjectID string, since time.Time, limit int) ([]*sso.LoginEntry, error) {
	if subjectID == "" {
		return nil, nil
	}
	s.mu.Lock()
	bucket := s.entries[subjectID]
	// Copy out under the lock — caller iterating shouldn't see
	// concurrent Append mutations.
	cp := make([]*sso.LoginEntry, 0, len(bucket))
	for _, e := range bucket {
		if !since.IsZero() && e.Timestamp.Before(since) {
			continue
		}
		entryCopy := *e
		cp = append(cp, &entryCopy)
	}
	s.mu.Unlock()
	// Sort newest first (Append order should already be near-time-
	// sorted, but the store doesn't promise monotonic Append-
	// timestamps in concurrent producers).
	sort.Slice(cp, func(i, j int) bool { return cp[i].Timestamp.After(cp[j].Timestamp) })
	if limit > 0 && len(cp) > limit {
		cp = cp[:limit]
	}
	return cp, nil
}

// PruneOlder removes entries with Timestamp < cutoff across every
// subject. Empty subject buckets are also dropped (idle subject
// cleanup). Returns total entries deleted.
func (s *MemoryRecentLoginStore) PruneOlder(_ context.Context, cutoff time.Time) (int64, error) {
	if cutoff.IsZero() {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var deleted int64
	for subj, bucket := range s.entries {
		kept := bucket[:0]
		for _, e := range bucket {
			if e.Timestamp.Before(cutoff) {
				deleted++
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			delete(s.entries, subj)
			continue
		}
		s.entries[subj] = kept
	}
	return deleted, nil
}

// HashLoginEntry builds a [sso.LoginEntry] from a [sso.LoginEvent]
// + an IP salt + a per-subject UA salt. The canonical helper —
// detector implementations call this rather than reaching for
// crypto/sha256 themselves, so the hash schema stays uniform
// across detectors + future store backends.
//
// ipSalt is a deployment-stable secret (operator-provided; rotates
// alongside the per-deployment audit redactor salt). uaSubjectSalt
// is per-subject so a captured UA hash doesn't correlate across
// users — typically derived deterministically from subjectID +
// ipSalt: `sha256(subjectID || ipSalt)[:8]`.
//
// Returns nil + empty error when event.SubjectID is empty
// (anonymous failure that detectors should skip).
func HashLoginEntry(event *sso.LoginEvent, ipSalt []byte) *sso.LoginEntry {
	if event == nil || event.SubjectID == "" {
		return nil
	}
	uaSubjectSalt := deriveUASubjectSalt(event.SubjectID, ipSalt)
	entry := &sso.LoginEntry{
		SubjectID: event.SubjectID,
		ClientID:  event.ClientID,
		Outcome:   event.Outcome,
		IPHash:    hashIP(event.RemoteIP, ipSalt),
		Timestamp: event.Timestamp,
	}
	if event.Geo != nil {
		entry.CountryCode = event.Geo.CountryCode
		entry.Latitude = event.Geo.Latitude
		entry.Longitude = event.Geo.Longitude
	}
	if event.UserAgent != "" {
		entry.UAFingerprintHash = hashUA(event.UserAgent, uaSubjectSalt)
	}
	return entry
}

// hashIP produces a salted 16-hex (64-bit) IP fingerprint. Truncated
// to keep the storage column narrow + fingerprint short enough not
// to become a strong identifier by itself. Salted so cross-deploy
// linkage requires the salt.
func hashIP(ip string, salt []byte) string {
	if ip == "" {
		return ""
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(ip))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// hashUA produces a per-subject-salted 16-hex (64-bit) UA
// fingerprint. The per-subject salt is the GDPR-friendly choice:
// even if the operator's audit log is dumped, captured UA hashes
// don't correlate device usage across users.
func hashUA(ua string, subjectSalt []byte) string {
	if ua == "" {
		return ""
	}
	h := sha256.New()
	h.Write(subjectSalt)
	h.Write([]byte(ua))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// deriveUASubjectSalt deterministically derives a per-subject salt
// from subjectID + the deployment ipSalt. Deterministic so detectors
// can re-derive on read; mixed with deployment salt so two
// deployments don't reuse the same per-subject salt for the same
// subjectID (cross-deployment correlation defeated).
func deriveUASubjectSalt(subjectID string, ipSalt []byte) []byte {
	h := sha256.New()
	h.Write(ipSalt)
	h.Write([]byte(":ua:"))
	h.Write([]byte(subjectID))
	sum := h.Sum(nil)
	return sum[:16]
}

// Compile-time interface assertion.
var _ sso.RecentLoginStore = (*MemoryRecentLoginStore)(nil)
