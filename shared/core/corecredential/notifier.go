package corecredential

import "context"

// Dependency names one class of external relying party that must react when a
// credential rotates or is compromised. The set is a small, bounded vocabulary
// (like CredentialType) so it stays safe as a bounded-cardinality audit/metric
// dimension and as a stable notification contract.
type Dependency string

const (
	// DependencyJWKS: the published /.well-known/jwks.json changed (a signing
	// or encryption key was added/removed) — relying parties must re-fetch it
	// before they can encrypt to / verify against the new key.
	DependencyJWKS Dependency = "jwks"
	// DependencySAMLMetadata: the SAML IdP/SP metadata document changed (a
	// signing or decryption key rotated) — SAML peers must re-fetch metadata.
	DependencySAMLMetadata Dependency = "saml_metadata"
	// DependencyWebhookReceivers: outbound webhook receivers must adopt the new
	// HMAC verification secret before the old one is retired.
	DependencyWebhookReceivers Dependency = "webhook_receivers"
)

// RotationNotice describes ONE credential change for the DependentPartyNotifier
// fan-out. It carries governance metadata only — never secret material — so it
// is safe to log, broadcast across replicas, and hand to any transport.
type RotationNotice struct {
	// Type is the credential class that changed.
	Type CredentialType
	// NewMeta is the freshly-installed active version's metadata.
	NewMeta CredentialMeta
	// Compromised distinguishes an emergency compromise-driven rotation (the
	// old version was retired INSTANTLY, no overlap) from a routine scheduled
	// rotation (the old version lingers through its overlap window).
	Compromised bool
	// Reason is the operator-supplied compromise justification. Empty for a
	// routine scheduled rotation.
	Reason string
	// Dependents is the set of relying-party classes this change affects, so a
	// notifier can target only the transports that matter for this credential.
	Dependents []Dependency
}

// DependentPartyNotifier signals affected relying parties that a credential
// rotated or was compromised (e.g. broadcast a JWKS-changed event, push a SAML
// metadata-update signal). It is an SPI: implementations own the transport;
// the framework only decides WHEN to fire and WHAT changed.
//
// Best-effort / fail-open: the caller logs a Notify error and never rolls back
// the rotation — by the time Notify runs the new secret is already installed
// and serving, so a failed notification must not wedge the rotation loop or the
// admin compromise request. The no-op default is NopDependentPartyNotifier;
// the memory recording reference impl is
// defaultimpl.MemoryDependentPartyNotifier.
type DependentPartyNotifier interface {
	Notify(ctx context.Context, notice RotationNotice) error
}

// DependencyReporter is an OPTIONAL CredentialRotator extension declaring which
// relying-party classes a rotation of ITS credential affects. The rotation
// framework reads it to populate RotationNotice.Dependents; a rotator that does
// not implement it produces notices with no dependents (nothing to notify).
type DependencyReporter interface {
	Dependents() []Dependency
}

// NopDependentPartyNotifier is the no-op DependentPartyNotifier used when no
// notifier is wired — every Notify succeeds silently, so the rotation framework
// can call it unconditionally.
type NopDependentPartyNotifier struct{}

func (NopDependentPartyNotifier) Notify(context.Context, RotationNotice) error { return nil }

var _ DependentPartyNotifier = NopDependentPartyNotifier{}
