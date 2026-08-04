package usageledger

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"time"
)

var (
	ErrSourceBindingRequired     = errors.New("usage ledger: source binding store required")
	ErrInvalidSourceBinding      = errors.New("usage ledger: invalid source binding")
	ErrSourceBindingConflict     = errors.New("usage ledger: source binding conflict")
	ErrSourceBindingUnauthorized = errors.New("usage ledger: source binding unauthorized")
)

const (
	maxBindingIdentityLength = 256
	maxAllowedDimensions     = 64
)

// SourceBinding is server-owned authorization data. Access-token subject and
// client_id select it; request bodies and forwarded headers never contribute
// tenant or source identity.
type SourceBinding struct {
	ID                string      `json:"id"`
	ClientID          string      `json:"client_id"`
	TenantID          string      `json:"tenant_id"`
	SourceSystem      string      `json:"source_system"`
	AllowedDimensions []Dimension `json:"allowed_dimensions"`
	Enabled           bool        `json:"enabled"`
	Revision          uint64      `json:"revision"`
	CreatedAt         time.Time   `json:"created_at"`
	UpdatedAt         time.Time   `json:"updated_at"`
}

func (b *SourceBinding) Validate() error {
	if b == nil || invalidBindingIdentity(b.ID) || invalidBindingIdentity(b.ClientID) ||
		invalidBindingIdentity(b.TenantID) || invalidBindingIdentity(b.SourceSystem) {
		return ErrInvalidSourceBinding
	}
	if b.Revision == 0 || b.Revision > math.MaxInt64 || b.CreatedAt.IsZero() ||
		b.UpdatedAt.IsZero() || b.UpdatedAt.Before(b.CreatedAt) {
		return ErrInvalidSourceBinding
	}
	return validateAllowedDimensions(b.AllowedDimensions)
}

// SourceBindingEvidence is an optimistic authorization lease. Durable stores
// recheck it inside the same transaction as the usage mutation; a disabled or
// revised binding therefore cannot authorize a later write from a stale
// handler lookup.
type SourceBindingEvidence struct {
	BindingID    string
	ClientID     string
	TenantID     string
	SourceSystem string
	Revision     uint64
}

func (e SourceBindingEvidence) Validate() error {
	if invalidBindingIdentity(e.BindingID) || invalidBindingIdentity(e.ClientID) ||
		invalidBindingIdentity(e.TenantID) || invalidBindingIdentity(e.SourceSystem) ||
		e.Revision == 0 || e.Revision > math.MaxInt64 {
		return ErrSourceBindingUnauthorized
	}
	return nil
}

func (b *SourceBinding) Evidence() SourceBindingEvidence {
	if b == nil {
		return SourceBindingEvidence{}
	}
	return SourceBindingEvidence{
		BindingID: b.ID, ClientID: b.ClientID, TenantID: b.TenantID,
		SourceSystem: b.SourceSystem, Revision: b.Revision,
	}
}

func (b *SourceBinding) Allows(dimension Dimension) bool {
	return b != nil && slices.Contains(b.AllowedDimensions, dimension)
}

func invalidBindingIdentity(value string) bool {
	return value == "" || strings.TrimSpace(value) != value || len(value) > maxBindingIdentityLength
}

func validateAllowedDimensions(dimensions []Dimension) error {
	if len(dimensions) > maxAllowedDimensions {
		return ErrInvalidSourceBinding
	}
	seen := make(map[Dimension]struct{}, len(dimensions))
	for _, dimension := range dimensions {
		value := string(dimension)
		if invalidBindingIdentity(value) {
			return ErrInvalidSourceBinding
		}
		if _, exists := seen[dimension]; exists {
			return ErrInvalidSourceBinding
		}
		seen[dimension] = struct{}{}
	}
	return nil
}

func cloneSourceBinding(binding *SourceBinding) *SourceBinding {
	if binding == nil {
		return nil
	}
	copy := *binding
	copy.AllowedDimensions = slices.Clone(binding.AllowedDimensions)
	return &copy
}

// SourceBindingStore owns optimistic mutation and lookup. Multiple disabled
// historical rows may share a client_id; implementations must prevent more
// than one enabled row, while the resolver still fails closed if drift ever
// produces ambiguity.
type SourceBindingStore interface {
	SaveSourceBinding(context.Context, *SourceBinding, uint64) (*SourceBinding, error)
	ListSourceBindingsByClient(context.Context, string) ([]*SourceBinding, error)
}

type SourceResolver struct {
	store SourceBindingStore
}

func NewSourceResolver(store SourceBindingStore) (*SourceResolver, error) {
	if store == nil {
		return nil, ErrSourceBindingRequired
	}
	return &SourceResolver{store: store}, nil
}

// Resolve returns an enabled, unique binding. Unknown clients, disabled-only
// clients, corrupt records, and ambiguous clients deliberately share one
// authorization error so the machine API cannot become a registration oracle.
func (r *SourceResolver) Resolve(ctx context.Context, clientID string) (*SourceBinding, error) {
	if invalidBindingIdentity(clientID) {
		return nil, ErrSourceBindingUnauthorized
	}
	bindings, err := r.store.ListSourceBindingsByClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	var resolved *SourceBinding
	for _, binding := range bindings {
		if binding == nil || !binding.Enabled {
			continue
		}
		if resolved != nil || binding.Validate() != nil || binding.ClientID != clientID {
			return nil, ErrSourceBindingUnauthorized
		}
		resolved = binding
	}
	if resolved == nil {
		return nil, ErrSourceBindingUnauthorized
	}
	return cloneSourceBinding(resolved), nil
}
