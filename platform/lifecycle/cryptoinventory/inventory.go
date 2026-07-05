package cryptoinventory

import (
	"context"
	"errors"
	"time"
)

// Purpose is the cryptographic operation one catalogued key entry serves.
type Purpose string

const (
	PurposeSign    Purpose = "sign"
	PurposeEncrypt Purpose = "encrypt"
	PurposeVerify  Purpose = "verify"
)

// Status is the lifecycle state of one catalogued key entry. The vocabulary
// mirrors corecredential.CredentialStatus (active/retiring/retired/
// compromised) so an operator reading both inventories sees one consistent
// lifecycle model, but is declared independently: this package catalogs
// material corecredential does not cover (signing keys, KMS keys, trust
// anchors), so it must not take on corecredential as a dependency merely for
// four string constants.
type Status string

const (
	StatusActive      Status = "active"
	StatusRetiring    Status = "retiring"
	StatusRetired     Status = "retired"
	StatusCompromised Status = "compromised"
)

// Entry is one catalogued piece of cryptographic key material. It NEVER
// carries secret or private key bytes — only the governance metadata safe to
// log and return from an admin endpoint (mirrors corecredential.CredentialMeta).
type Entry struct {
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm,omitempty"`
	Purpose   Purpose   `json:"purpose"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	Status    Status    `json:"status"`

	// BackingStore names WHERE the key material actually lives: "memory",
	// "file", or "kms:<provider>" (e.g. "kms:awskms") for an HSM/cloud-KMS-
	// backed key whose private material never enters this process.
	BackingStore string `json:"backing_store,omitempty"`

	// Source identifies which registered Source produced this entry
	// ("signingkeys", "rotation", or a caller-chosen static-source name) —
	// the audit trail for "who told the inventory about this key".
	Source string `json:"source"`

	// CompromisedAt / CompromiseReason are set by ReportKeyCompromise ONLY —
	// no Source ever reports these directly (reporting a compromise is
	// bookkeeping this package owns, not a fact pulled from elsewhere).
	CompromisedAt    time.Time `json:"compromised_at,omitzero"`
	CompromiseReason string    `json:"compromise_reason,omitempty"`
}

// Filter narrows ListKeys. A zero Filter matches every catalogued entry.
type Filter struct {
	Status    Status
	Purpose   Purpose
	Algorithm string
}

// Match reports whether e satisfies every non-empty field of f.
func (f Filter) Match(e Entry) bool {
	if f.Status != "" && e.Status != f.Status {
		return false
	}
	if f.Purpose != "" && e.Purpose != f.Purpose {
		return false
	}
	if f.Algorithm != "" && e.Algorithm != f.Algorithm {
		return false
	}
	return true
}

// ErrKeyNotFound is returned by ReportKeyCompromise when keyID matches no
// entry across any registered Source — mirrors corecredential.ErrCredentialNotFound.
var ErrKeyNotFound = errors.New("cryptoinventory: key not found")

// Source is the narrow read-only SPI each cryptographic-material concern
// implements directly, or through a small adapter, so an Inventory can PULL
// its current key metadata without owning or duplicating the material
// itself. Signing keys, JWE keys, KMS-backed keys, and mTLS trust anchors
// each get their own Source (or share one — source_rotation.go's adapter
// over platform/lifecycle/rotation.Registry covers every corecredential-
// registered class in one Source).
type Source interface {
	// Name identifies this source ("signingkeys", "rotation", "kms",
	// "mtls_trust_anchors", ...) for Entry.Source.
	Name() string
	// Keys returns the current governance metadata for every key this
	// source holds RIGHT NOW — a live pull, never a cached duplicate.
	Keys(ctx context.Context) ([]Entry, error)
}

// Retirer is the OPTIONAL Source extension a concern implements when it can
// trigger ITS OWN key-retirement mechanism on demand (e.g. a signing-key
// issuer's RetireKey/DropVerifyKey, or platform/lifecycle/rotation's
// emergency Compromise path). ReportKeyCompromise calls it best-effort:
// retirement is NOT this package's job (see the package doc) — a Source
// that cannot retire on demand simply leaves the key recorded compromised
// without being dropped from its own live verify/accept set.
type Retirer interface {
	RetireKey(ctx context.Context, keyID string) error
}

// Inventory catalogs cryptographic key material aggregated live from
// registered Sources, with a compromise-bookkeeping overlay this package
// itself owns (see the package doc for the bookkeeping-vs-revocation split).
type Inventory interface {
	// ListKeys returns every catalogued key matching f (a zero Filter
	// matches everything), pulled fresh from every registered Source with
	// the compromise overlay applied.
	ListKeys(ctx context.Context, f Filter) ([]Entry, error)
	// ReportKeyCompromise records keyID as compromised — bookkeeping and
	// alerting only, NEVER the authoritative revocation (see the package
	// doc) — and, when the owning Source also implements Retirer,
	// best-effort invokes its RetireKey. Returns the updated Entry, or
	// ErrKeyNotFound when keyID matches no key currently reported by any
	// registered Source.
	ReportKeyCompromise(ctx context.Context, keyID, reason string) (Entry, error)
}
