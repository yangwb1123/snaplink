// Package quotabinding owns the versioned machine-source authorization set
// used by Snaplink's tenant quota projection ingress.
package quotabinding

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/yangwb1123/snaplink/shared/core"
)

var (
	ErrInvalidSource   = errors.New("tenant quota binding: invalid source")
	ErrConflict        = errors.New("tenant quota binding: revision conflict")
	ErrStale           = errors.New("tenant quota binding: stale revision")
	ErrNoEnabledSource = errors.New("tenant quota binding: no enabled source")
)

const maxIdentityLength = 256

// Source is immutable in identity (ID/client/tenant/source) and mutable only
// in Enabled through monotonic Revision updates. A new source starts at one.
type Source struct {
	ID           string `json:"id" yaml:"id"`
	ClientID     string `json:"client_id" yaml:"client_id"`
	TenantID     string `json:"tenant_id" yaml:"tenant_id"`
	SourceSystem string `json:"source_system" yaml:"source_system"`
	Enabled      bool   `json:"enabled" yaml:"enabled"`
	Revision     uint64 `json:"revision" yaml:"revision"`
}

func (s Source) Validate() error {
	if !ValidIdentity(s.ID) || !ValidIdentity(s.ClientID) || !ValidIdentity(s.SourceSystem) ||
		core.ValidateQuotaTenantID(s.TenantID) != nil || s.Revision == 0 ||
		s.Revision > core.TenantQuotaMaxRevision {
		return ErrInvalidSource
	}
	return nil
}

// ValidIdentity bounds operator-owned identifiers used in exact lookup keys.
func ValidIdentity(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maxIdentityLength &&
		!strings.ContainsAny(value, "\r\n")
}

type bindingKey struct {
	clientID     string
	sourceSystem string
}

// Registry atomically serves an immutable snapshot while desired-state
// generations are reconciled. Omitted bindings are retained; disabling one
// requires an explicit next-revision record, preventing accidental deletion.
type Registry struct {
	mu         sync.RWMutex
	sources    map[string]Source
	bindings   map[bindingKey]string
	desiredErr error
}

func NewRegistry(sources []Source) (*Registry, error) {
	byID, bindings, err := validateSourceSet(sources)
	if err != nil {
		return nil, err
	}
	return &Registry{sources: byID, bindings: bindings}, nil
}

// Resolve returns authority only for an enabled exact
// (validated client_id, source_system) pair.
func (r *Registry) Resolve(clientID, sourceSystem string) (string, bool) {
	if r == nil || !ValidIdentity(clientID) || !ValidIdentity(sourceSystem) {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenantID, ok := r.bindings[bindingKey{clientID, sourceSystem}]
	return tenantID, ok
}

// Ready reports whether the enabled ingress has at least one authorized
// source. An all-disabled desired state is fail-closed and readiness-visible.
func (r *Registry) Ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil {
		return ErrNoEnabledSource
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.desiredErr != nil {
		return r.desiredErr
	}
	if len(r.bindings) == 0 {
		return ErrNoEnabledSource
	}
	return nil
}

// ApplyDesired atomically applies one or more desired source generations.
// Stale records are ignored, equal revisions must be byte-equivalent, and a
// changed source must advance exactly one revision without changing identity.
func (r *Registry) ApplyDesired(desired []Source) (bool, error) {
	if r == nil {
		return false, ErrInvalidSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(desired) == 0 {
		r.desiredErr = ErrInvalidSource
		return false, ErrInvalidSource
	}
	if _, _, err := validateSourceSet(desired); err != nil {
		r.desiredErr = err
		return false, err
	}
	candidate := cloneSources(r.sources)
	changed := false
	for _, proposed := range desired {
		applied, err := applyDesiredSource(candidate, proposed)
		if err != nil {
			r.desiredErr = err
			return false, err
		}
		changed = changed || applied
	}
	if !changed {
		r.desiredErr = nil
		return false, nil
	}
	byID, bindings, err := validateSourceSet(sourceValues(candidate))
	if err != nil {
		r.desiredErr = err
		return false, err
	}
	r.sources, r.bindings = byID, bindings
	r.desiredErr = nil
	return true, nil
}

func applyDesiredSource(current map[string]Source, proposed Source) (bool, error) {
	if proposed.Validate() != nil {
		return false, ErrInvalidSource
	}
	stored, exists := current[proposed.ID]
	if !exists {
		if proposed.Revision != 1 {
			return false, ErrConflict
		}
		current[proposed.ID] = proposed
		return true, nil
	}
	if proposed.Revision < stored.Revision {
		return false, ErrStale
	}
	if proposed.Revision == stored.Revision {
		if proposed != stored {
			return false, ErrConflict
		}
		return false, nil
	}
	if proposed.Revision != stored.Revision+1 || !sameSourceIdentity(stored, proposed) {
		return false, ErrConflict
	}
	current[proposed.ID] = proposed
	return true, nil
}

func validateSourceSet(
	sources []Source,
) (map[string]Source, map[bindingKey]string, error) {
	byID := make(map[string]Source, len(sources))
	bindings := make(map[bindingKey]string, len(sources))
	keys := make(map[bindingKey]struct{}, len(sources))
	sourceOwners := make(map[string]string, len(sources))
	for _, source := range sources {
		if source.Validate() != nil {
			return nil, nil, ErrInvalidSource
		}
		if _, duplicate := byID[source.ID]; duplicate {
			return nil, nil, ErrConflict
		}
		key := bindingKey{source.ClientID, source.SourceSystem}
		if _, duplicate := keys[key]; duplicate {
			return nil, nil, ErrConflict
		}
		if owner, exists := sourceOwners[source.SourceSystem]; exists && owner != source.TenantID {
			return nil, nil, ErrConflict
		}
		byID[source.ID], sourceOwners[source.SourceSystem], keys[key] = source, source.TenantID, struct{}{}
		if source.Enabled {
			bindings[key] = source.TenantID
		}
	}
	return byID, bindings, nil
}

func sameSourceIdentity(left, right Source) bool {
	return left.ID == right.ID && left.ClientID == right.ClientID &&
		left.TenantID == right.TenantID && left.SourceSystem == right.SourceSystem
}

func cloneSources(values map[string]Source) map[string]Source {
	copy := make(map[string]Source, len(values))
	for id, source := range values {
		copy[id] = source
	}
	return copy
}

func sourceValues(values map[string]Source) []Source {
	result := make([]Source, 0, len(values))
	for _, source := range values {
		result = append(result, source)
	}
	return result
}

func (r *Registry) Snapshot() []Source {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := sourceValues(r.sources)
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}
