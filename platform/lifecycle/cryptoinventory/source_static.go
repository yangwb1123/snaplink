package cryptoinventory

import "context"

// StaticSource is a small adapter for cryptographic material that has no
// live Go introspection seam in this SDK:
//
//   - A KMS-backed signing key: the concrete provider clients
//     (infrastructure/kms/{awskms,gcpkms,azurekeyvault,pkcs11}) are separate,
//     optional Go modules that only the composition root wires — a platform
//     package may not import them (AGENTS.md §0.2) — and each exposes only
//     the stdlib crypto.Signer seam (no exported KeyID/Algorithm accessor).
//   - An mTLS trust anchor: this SDK loads trust anchors into an opaque
//     x509.CertPool with no retained per-entry metadata.
//
// The composition root registers a StaticSource with the entries it already
// knows about at wiring time (it holds the key id, algorithm, and provider
// name as the very values it used to construct the concrete signer/pool).
type StaticSource struct {
	SourceName string
	Entries    []Entry
	// OnRetire, when set, is called by RetireKey for a matching keyID — e.g.
	// removing a trust anchor from the live pool, or disabling a KMS key
	// alias. Nil leaves this Source read-only for retirement (the
	// compromise report still records the bookkeeping).
	OnRetire func(ctx context.Context, keyID string) error
}

var _ Source = (*StaticSource)(nil)
var _ Retirer = (*StaticSource)(nil)

func (s *StaticSource) Name() string { return s.SourceName }

// Keys returns a copy of s.Entries, defaulting each entry's Source field to
// s.SourceName when the caller left it unset.
func (s *StaticSource) Keys(context.Context) ([]Entry, error) {
	out := make([]Entry, len(s.Entries))
	for i, e := range s.Entries {
		if e.Source == "" {
			e.Source = s.SourceName
		}
		out[i] = e
	}
	return out, nil
}

// RetireKey best-effort delegates to OnRetire. A nil OnRetire is a no-op —
// this Source is then read-only for retirement, but ReportKeyCompromise
// still records the bookkeeping.
func (s *StaticSource) RetireKey(ctx context.Context, keyID string) error {
	if s.OnRetire == nil {
		return ErrRetirementUnsupported
	}
	return s.OnRetire(ctx, keyID)
}
