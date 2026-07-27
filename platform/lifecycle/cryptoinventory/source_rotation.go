package cryptoinventory

import (
	"context"
	"sync"

	"github.com/yangwb1123/snaplink/platform/lifecycle/rotation"
	"github.com/yangwb1123/snaplink/shared/core/corecredential"
)

// RotationSourceName is the default Entry.Source / Name() for a
// RotationSource.
const RotationSourceName = "rotation"

// RotationSource adapts a platform/lifecycle/rotation.Registry to a Source,
// surfacing every corecredential-registered credential class (e.g. the JWE
// request-object decryption key, the outbound webhook HMAC secret) as
// catalogued key entries — reusing the registry's OWN Inventory() snapshot
// rather than re-deriving one, so this is a pure projection, never a second
// source of truth.
type RotationSource struct {
	Registry *rotation.Registry
	// Scheduler, when set, backs RetireKey via its emergency Compromise
	// path — the SAME force-rotate-off-schedule mechanism
	// POST /api/v1/admin/credentials/{type}/compromise already drives. Nil
	// leaves this Source read-only for retirement (ReportKeyCompromise
	// still records the bookkeeping; nothing gets force-rotated).
	Scheduler *rotation.Scheduler

	mu    sync.Mutex
	types map[string]corecredential.CredentialType // keyID -> type, refreshed by every Keys() call
}

var _ Source = (*RotationSource)(nil)
var _ Retirer = (*RotationSource)(nil)

func (s *RotationSource) Name() string { return RotationSourceName }

// Keys projects the registry's governance inventory into cryptoinventory
// Entries.
func (s *RotationSource) Keys(context.Context) ([]Entry, error) {
	if s.Registry == nil {
		return nil, nil
	}
	inv := s.Registry.Inventory()
	out := make([]Entry, 0, len(inv))
	types := make(map[string]corecredential.CredentialType, len(inv))
	for _, item := range inv {
		types[item.ID] = item.Type
		out = append(out, Entry{
			KeyID:        item.ID,
			Algorithm:    item.Algorithm,
			Purpose:      credentialPurpose(item.Type),
			CreatedAt:    item.CreatedAt,
			Status:       rotationStatus(item.Status),
			BackingStore: "memory",
			Source:       RotationSourceName,
		})
	}
	s.mu.Lock()
	s.types = types
	s.mu.Unlock()
	return out, nil
}

// RetireKey maps keyID back to its CredentialType (populated by the most
// recent Keys() call) and drives the SAME emergency Compromise path the
// credential-compromise admin endpoint uses. A nil Scheduler, or a keyID this
// Source's last Keys() pull didn't recognize, is a no-op — the caller's
// compromise-bookkeeping record still stands regardless.
func (s *RotationSource) RetireKey(ctx context.Context, keyID string) error {
	if s.Scheduler == nil {
		return nil
	}
	s.mu.Lock()
	credType, ok := s.types[keyID]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	_, err := s.Scheduler.Compromise(ctx, credType, "cryptoinventory: key reported compromised")
	return err
}

// credentialPurpose maps a corecredential.CredentialType to this package's
// Purpose vocabulary. Every class registered with the rotation framework
// today produces a MAC or ciphertext rather than a verifiable signature
// consumers check independently, so "sign" is the safe default for any
// class not explicitly mapped below.
func credentialPurpose(t corecredential.CredentialType) Purpose {
	if t == corecredential.CredentialTypeJWEDecryption {
		return PurposeEncrypt
	}
	return PurposeSign
}

// rotationStatus maps a corecredential.CredentialStatus to this package's
// Status vocabulary. The two vocabularies share the same four values by
// design (see inventory.go's Status doc), so this is a direct 1:1 mapping.
func rotationStatus(s corecredential.CredentialStatus) Status {
	switch s {
	case corecredential.CredentialStatusRetiring:
		return StatusRetiring
	case corecredential.CredentialStatusRetired:
		return StatusRetired
	case corecredential.CredentialStatusCompromised:
		return StatusCompromised
	default:
		return StatusActive
	}
}
