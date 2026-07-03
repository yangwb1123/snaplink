package corecredential

import (
	"context"
	"time"
)

// CredentialStatusStore tracks governance metadata + lifecycle status per
// credential VERSION. Metadata only — secret material never passes through
// this interface, so any backend (memory, sqlite, etcd) can hold it without
// entering the secret-handling trust boundary.
//
// The memory reference implementation is
// defaultimpl.MemoryCredentialStatusStore.
type CredentialStatusStore interface {
	// Upsert inserts or replaces the record for (meta.Type, meta.ID).
	Upsert(ctx context.Context, meta CredentialMeta) error

	// Get returns one version's record. ErrCredentialNotFound when the
	// (type, id) pair is unknown.
	Get(ctx context.Context, credType CredentialType, id string) (CredentialMeta, error)

	// ListByType returns every tracked version of one credential class,
	// ordered by ascending Version so "current" is last.
	ListByType(ctx context.Context, credType CredentialType) ([]CredentialMeta, error)

	// UpdateStatus transitions one version's lifecycle status.
	// ErrCredentialNotFound when the (type, id) pair is unknown.
	UpdateStatus(ctx context.Context, credType CredentialType, id string, status CredentialStatus) error
}

// CredentialRotator rotates ONE credential class. Implementations own the
// secret material end-to-end: Rotate mints a fresh secret, installs it into
// the live consumer (signer, issuer, transport), and returns metadata only.
//
// Contract: when Rotate fails, the previously-installed credential MUST
// remain installed and serving — the framework never trades a working old
// credential for a broken new one (no zero-usable-credentials state).
type CredentialRotator interface {
	// Type identifies the credential class this rotator manages. One
	// rotator per type may be registered with a rotation.Registry.
	Type() CredentialType

	// Rotate mints + installs a new credential version and returns its
	// governance metadata (Status active, fresh Version/CreatedAt).
	Rotate(ctx context.Context) (CredentialMeta, error)

	// OverlapWindow hints how long the demoted previous version must stay
	// accepted (verify-only) after a rotation so asynchronous consumers
	// migrate before the old credential is retired. Signing credentials
	// need windows >= the longest consumer retry/redelivery horizon.
	OverlapWindow() time.Duration
}
