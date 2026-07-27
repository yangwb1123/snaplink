// Package rotation is the unified credential-rotation framework: subsystems
// register a corecredential.CredentialRotator per credential class with a
// rotation interval, and the Scheduler drives them — due-time tracking,
// overlap-window retirement, failure retry with backoff, and a governance
// inventory for the admin API. Secret material never enters this package;
// rotators install secrets into their own backends and hand back metadata.
package rotation

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core/corecredential"
)

// ErrDuplicateRotator is returned by Registry.Register when a rotator for
// the same CredentialType is already registered — one rotator owns each
// credential class, so a duplicate is a wiring bug, not a runtime state.
var ErrDuplicateRotator = errors.New("sso: rotation: rotator already registered for credential type")

// CurrentMetaProvider is an OPTIONAL CredentialRotator extension reporting
// the version installed at registration time, so the inventory (and the
// status store seed) show the live credential before the scheduler's first
// rotation fires. Without it a class lists as version-unknown until rotated.
type CurrentMetaProvider interface {
	CurrentMeta() corecredential.CredentialMeta
}

// entry is one registered credential class plus its scheduling state. All
// access goes through the Registry mutex; the Scheduler is the only mutator.
type entry struct {
	rotator  corecredential.CredentialRotator
	interval time.Duration

	nextDue  time.Time
	failures int // consecutive rotation failures; drives the retry backoff

	current  corecredential.CredentialMeta  // zero Version until known
	retiring *corecredential.CredentialMeta // demoted version inside its overlap window
}

// Registry holds the registered rotators plus their scheduling state.
// Register everything at boot, then hand the registry to ONE Scheduler
// (multi-replica deployments run the scheduler on a single replica — the
// same single-rotator constraint as the signing-key rotation loop).
type Registry struct {
	mu      sync.Mutex
	entries map[corecredential.CredentialType]*entry
	order   []corecredential.CredentialType // stable inventory order = registration order
}

func NewRegistry() *Registry {
	return &Registry{entries: make(map[corecredential.CredentialType]*entry)}
}

// Register adds one rotator with its rotation interval. The first rotation
// fires one full interval AFTER registration, so a freshly-seeded credential
// serves a whole period (mirrors the signing-key StartRotation contract).
func (r *Registry) Register(rot corecredential.CredentialRotator, interval time.Duration) error {
	if rot == nil {
		return errors.New("sso: rotation: nil rotator")
	}
	if interval <= 0 {
		return fmt.Errorf("sso: rotation: non-positive interval %v for %q", interval, rot.Type())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	credType := rot.Type()
	if _, dup := r.entries[credType]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateRotator, credType)
	}
	e := &entry{rotator: rot, interval: interval, nextDue: time.Now().Add(interval)}
	if p, ok := rot.(CurrentMetaProvider); ok {
		e.current = p.CurrentMeta()
	}
	r.entries[credType] = e
	r.order = append(r.order, credType)
	return nil
}

// InventoryEntry is one credential version in the governance inventory —
// metadata plus, for the active version, when its next rotation is due.
// NEVER carries secret material.
type InventoryEntry struct {
	corecredential.CredentialMeta
	NextRotation time.Time `json:"next_rotation,omitzero"`
}

// Inventory snapshots every registered class: the active version (with its
// next due time) and, during an overlap window, the retiring one. A class
// whose live version is unknown (no CurrentMetaProvider, not yet rotated)
// still lists with its Type + due time so operators see it is managed.
func (r *Registry) Inventory() []InventoryEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]InventoryEntry, 0, len(r.order))
	for _, credType := range r.order {
		e := r.entries[credType]
		cur := e.current
		if cur.Type == "" {
			cur.Type = credType
		}
		out = append(out, InventoryEntry{CredentialMeta: cur, NextRotation: e.nextDue})
		if e.retiring != nil {
			out = append(out, InventoryEntry{CredentialMeta: *e.retiring})
		}
	}
	return out
}

// dueRotation is the lock-free snapshot the Scheduler rotates with: Rotate
// may block on IO, so it must run outside the registry mutex.
type dueRotation struct {
	credType corecredential.CredentialType
	rotator  corecredential.CredentialRotator
}

func (r *Registry) due(now time.Time) []dueRotation {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []dueRotation
	for _, credType := range r.order {
		if e := r.entries[credType]; !now.Before(e.nextDue) {
			out = append(out, dueRotation{credType: credType, rotator: e.rotator})
		}
	}
	return out
}

// applySuccess installs the new active meta, demotes the previous version
// into its overlap window, and schedules the next regular rotation. Returns
// the demoted meta (nil when no previous version was known) + next due time.
func (r *Registry) applySuccess(credType corecredential.CredentialType, meta corecredential.CredentialMeta, now time.Time) (*corecredential.CredentialMeta, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[credType]
	if !ok {
		return nil, time.Time{}
	}
	var demoted *corecredential.CredentialMeta
	if prev := e.current; prev.Version > 0 {
		prev.Status = corecredential.CredentialStatusRetiring
		prev.NotAfter = now.Add(e.rotator.OverlapWindow())
		demoted = &prev
	}
	e.current = meta
	e.retiring = demoted
	e.failures = 0
	e.nextDue = now.Add(e.interval)
	return demoted, e.nextDue
}

// applyFailure schedules the retry: doubling backoff per consecutive
// failure, capped. The entry's current/retiring state is untouched — the
// old credential keeps serving (CredentialRotator contract).
func (r *Registry) applyFailure(credType corecredential.CredentialType, now time.Time, base, maxDelay time.Duration) (int, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[credType]
	if !ok {
		return 0, time.Time{}
	}
	e.failures++
	e.nextDue = now.Add(nextRetryDelay(base, maxDelay, e.failures))
	return e.failures, e.nextDue
}

// rotatorFor returns the rotator registered for credType. ok is false for an
// unregistered class — the compromise path maps that to ErrUnknownCredentialType.
func (r *Registry) rotatorFor(credType corecredential.CredentialType) (corecredential.CredentialRotator, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[credType]
	if !ok {
		return nil, false
	}
	return e.rotator, true
}

// applyCompromise installs the emergency replacement version and, UNLIKE
// applySuccess, keeps NO overlap window: the previously-active version is
// marked compromised and the demoted-retiring version (if any) is force-retired
// — both drop out of the live snapshot immediately, mirroring the rotator's
// RotateCompromised, which retired the old SECRET the instant it minted the new
// one. Returns the compromised (previously-active) + force-retired metas for
// status-store/audit fan-out, plus the next regular due time. ok is false for
// an unknown class (never registered).
func (r *Registry) applyCompromise(credType corecredential.CredentialType, meta corecredential.CredentialMeta, now time.Time) (compromised, retired *corecredential.CredentialMeta, next time.Time, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, found := r.entries[credType]
	if !found {
		return nil, nil, time.Time{}, false
	}
	if prev := e.current; prev.Version > 0 {
		prev.Status = corecredential.CredentialStatusCompromised
		prev.NotAfter = now // no overlap: leaked version is not accepted past now
		compromised = &prev
	}
	if e.retiring != nil {
		forced := *e.retiring
		forced.Status = corecredential.CredentialStatusRetired
		forced.NotAfter = now
		retired = &forced
	}
	e.current = meta
	e.retiring = nil
	e.failures = 0
	e.nextDue = now.Add(e.interval)
	return compromised, retired, e.nextDue, true
}

// retireDue collapses overlap windows that have closed: each retiring
// version at/past its NotAfter is dropped from the live snapshot and
// returned with Status retired for store/audit fan-out.
func (r *Registry) retireDue(now time.Time) []corecredential.CredentialMeta {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []corecredential.CredentialMeta
	for _, credType := range r.order {
		e := r.entries[credType]
		if e.retiring == nil || now.Before(e.retiring.NotAfter) {
			continue
		}
		m := *e.retiring
		m.Status = corecredential.CredentialStatusRetired
		e.retiring = nil
		out = append(out, m)
	}
	return out
}

// activeMetas snapshots the known active versions (for the age gauge +
// status-store seeding).
func (r *Registry) activeMetas() []corecredential.CredentialMeta {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []corecredential.CredentialMeta
	for _, credType := range r.order {
		if e := r.entries[credType]; e.current.Version > 0 {
			out = append(out, e.current)
		}
	}
	return out
}

// nextRetryDelay is the rotation-failure backoff: base doubled per
// consecutive failure, capped at maxDelay (the loop caps before doubling so
// pathological failure counts cannot overflow the duration).
func nextRetryDelay(base, maxDelay time.Duration, failures int) time.Duration {
	d := base
	for i := 1; i < failures; i++ {
		if d >= maxDelay {
			return maxDelay
		}
		d *= 2
	}
	if d > maxDelay {
		return maxDelay
	}
	return d
}
