package cryptoinventory

import (
	"context"
	"errors"
	"sync"
	"time"
)

// compromiseRecord is the bookkeeping MemoryInventory retains for one
// reported-compromised key id. It is deliberately tiny — no key material,
// nothing a Source doesn't already tell us except the fact of the report.
type compromiseRecord struct {
	at               time.Time
	reason           string
	retirementStatus RetirementStatus
	retirementError  string
}

// MemoryInventory is the process-local, non-durable Inventory reference
// implementation (AGENTS.md "no mocks" — every SDK concern is an interface
// plus a real memory impl). A restart loses the compromise-bookkeeping
// overlay; the Sources themselves are unaffected, since they own their own
// material independently of this package.
type MemoryInventory struct {
	sources []Source

	mu          sync.RWMutex
	compromised map[string]compromiseRecord // keyID -> record
}

var _ Inventory = (*MemoryInventory)(nil)

// NewMemoryInventory returns a ready MemoryInventory pulling from sources.
// ListKeys and ReportKeyCompromise aggregate across every source, in the
// given order.
func NewMemoryInventory(sources ...Source) *MemoryInventory {
	return &MemoryInventory{
		sources:     sources,
		compromised: make(map[string]compromiseRecord),
	}
}

// ListKeys pulls a fresh snapshot from every registered Source, applies the
// compromise overlay (a keyID reported compromised always shows Status
// compromised regardless of what its Source currently reports), and returns
// only the entries matching f.
func (m *MemoryInventory) ListKeys(ctx context.Context, f Filter) ([]Entry, error) {
	entries := m.pull(ctx)
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if f.Match(e) {
			out = append(out, e)
		}
	}
	return out, nil
}

// pull aggregates every Source's live Keys(), applying the compromise
// overlay to each. A single Source error does not fail the whole call —
// fail-open toward observability, so an inventory read keeps reporting the
// sources it CAN reach even when one is temporarily unavailable.
func (m *MemoryInventory) pull(ctx context.Context) []Entry {
	var out []Entry
	for _, src := range m.sources {
		keys, err := src.Keys(ctx)
		if err != nil {
			continue
		}
		for _, e := range keys {
			out = append(out, m.applyOverlay(e))
		}
	}
	return out
}

// applyOverlay stamps e with the compromise-bookkeeping overlay when keyID
// was previously reported via ReportKeyCompromise.
func (m *MemoryInventory) applyOverlay(e Entry) Entry {
	m.mu.RLock()
	rec, compromised := m.compromised[e.KeyID]
	m.mu.RUnlock()
	if !compromised {
		return e
	}
	e.Status = StatusCompromised
	e.CompromisedAt = rec.at
	e.CompromiseReason = rec.reason
	e.RetirementStatus = rec.retirementStatus
	e.RetirementError = rec.retirementError
	return e
}

// ReportKeyCompromise records keyID compromised and best-effort triggers
// retirement on whichever registered Source currently owns it (when that
// Source also implements Retirer). ErrKeyNotFound when no Source's current
// Keys() lists keyID.
func (m *MemoryInventory) ReportKeyCompromise(ctx context.Context, keyID, reason string) (Entry, error) {
	entry, source, retirer, found := m.locate(ctx, keyID)
	if !found {
		return Entry{}, ErrKeyNotFound
	}

	now := time.Now().UTC()
	retirementStatus, retirementError := retirementOutcome(ctx, source, retirer, keyID)
	m.mu.Lock()
	m.compromised[keyID] = compromiseRecord{
		at: now, reason: reason,
		retirementStatus: retirementStatus, retirementError: retirementError,
	}
	m.mu.Unlock()

	entry.Status = StatusCompromised
	entry.CompromisedAt = now
	entry.CompromiseReason = reason
	entry.RetirementStatus = retirementStatus
	entry.RetirementError = retirementError
	return entry, nil
}

func retirementOutcome(
	ctx context.Context, source Source, retirer Retirer, keyID string,
) (RetirementStatus, string) {
	if retirer == nil {
		return RetirementUnsupported, ""
	}
	if err := retirer.RetireKey(ctx, keyID); err != nil {
		if errors.Is(err, ErrRetirementUnsupported) {
			return RetirementUnsupported, ""
		}
		return RetirementFailed, err.Error()
	}
	keys, err := source.Keys(ctx)
	if err != nil {
		return RetirementPending, err.Error()
	}
	for _, key := range keys {
		if key.KeyID == keyID && key.Status != StatusRetired && key.Status != StatusCompromised {
			return RetirementPending, ""
		}
	}
	return RetirementCompleted, ""
}

func (m *MemoryInventory) locate(
	ctx context.Context, keyID string,
) (Entry, Source, Retirer, bool) {
	for _, src := range m.sources {
		keys, err := src.Keys(ctx)
		if err != nil {
			continue
		}
		for _, e := range keys {
			if e.KeyID == keyID {
				r, _ := src.(Retirer)
				return e, src, r, true
			}
		}
	}
	return Entry{}, nil, nil, false
}
