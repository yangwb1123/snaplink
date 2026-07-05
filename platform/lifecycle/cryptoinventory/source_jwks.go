package cryptoinventory

import (
	"context"

	"github.com/snaplink/sso/shared/core"
)

// JWKSSourceName is the default Entry.Source / Name() for a JWKSSource.
const JWKSSourceName = "signingkeys"

// keyRetirer is the ad hoc interface satisfied by every SDK signing-key
// TokenIssuer (Ed25519JWTIssuer, ECDSAJWTIssuer, RSAJWTIssuer). Declaring it
// here — rather than importing an issuer's concrete type from
// infrastructure/defaultimpl — keeps this package decoupled from that layer:
// a platform package may not import infrastructure (AGENTS.md §0.2
// dependency direction). This is the exact duck-typed seam
// interfaces/sso.runCoordinatedRetire already uses for the same reason.
type keyRetirer interface {
	RetireKey(kid string) error
}

// keyDropper is the verify-only counterpart of keyRetirer — an adopted
// peer/coordinated-rotation key has no local RetireKey (it isn't this
// replica's own key), only DropVerifyKey.
type keyDropper interface {
	DropVerifyKey(kid string)
}

// JWKSSource adapts every core.JWKSProvider in Issuers to a Source,
// producing one Entry per currently-published JWK — the union of active and
// verify-only signing keys every registered TokenIssuer serves. It is the
// signing-key half of the inventory: platform/signingkeys' leaderless
// aggregation republishes adopted peer keys through the SAME JWKS() calls,
// so this Source sees them too without a second integration.
//
// The JWKS wire format (shared/core.JWK) carries no created-at field and no
// active-vs-retiring distinction, so every entry defaults to Status active —
// a real distinction (retiring/compromised) only ever appears here via the
// compromise overlay MemoryInventory applies on top.
type JWKSSource struct {
	// Issuers is the server's token-issuer set (e.g. Server.TokenIssuers()).
	// Issuers not implementing core.JWKSProvider (symmetric/opaque issuers)
	// are silently skipped, mirroring the JWKS endpoint's own aggregation.
	Issuers map[string]core.TokenIssuer
	// BackingStore labels where the signing PRIVATE key lives — "memory"
	// for an in-process issuer, or "kms:<provider>" when the issuer was
	// wired with an external KMS-backed crypto.Signer. Defaults to
	// "memory" when empty.
	BackingStore string
}

var _ Source = (*JWKSSource)(nil)
var _ Retirer = (*JWKSSource)(nil)

func (s *JWKSSource) Name() string { return JWKSSourceName }

// Keys returns one Entry per JWK currently published by any JWKSProvider
// issuer in s.Issuers.
func (s *JWKSSource) Keys(ctx context.Context) ([]Entry, error) {
	store := s.BackingStore
	if store == "" {
		store = "memory"
	}
	var out []Entry
	for _, ti := range s.Issuers {
		jp, ok := ti.(core.JWKSProvider)
		if !ok {
			continue
		}
		jwks, err := jp.JWKS(ctx)
		if err != nil {
			continue
		}
		for _, jwk := range jwks {
			out = append(out, Entry{
				KeyID:        jwk.Kid,
				Algorithm:    jwk.Alg,
				Purpose:      purposeFromUse(jwk.Use),
				Status:       StatusActive,
				BackingStore: store,
				Source:       JWKSSourceName,
			})
		}
	}
	return out, nil
}

// RetireKey implements Retirer, trying every registered issuer's own
// RetireKey (the kid is this replica's demoted signing key) AND
// DropVerifyKey (the kid is an adopted peer/coordinated-rotation key held
// verify-only) — the same two-seam, best-effort try
// interfaces/sso.runCoordinatedRetire uses, since a compromised kid can be
// either kind depending on the deployment. A kid neither seam recognizes is
// simply a no-op (the key stays recorded compromised regardless).
func (s *JWKSSource) RetireKey(_ context.Context, keyID string) error {
	for _, ti := range s.Issuers {
		if r, ok := ti.(keyRetirer); ok {
			_ = r.RetireKey(keyID)
		}
		if d, ok := ti.(keyDropper); ok {
			d.DropVerifyKey(keyID)
		}
	}
	return nil
}

// purposeFromUse maps a JWK's RFC 7517 "use" to this package's Purpose
// vocabulary. "sig" and an absent use both mean signing (the SDK's issuers
// omit "use" on many keys); "enc" is the JWE-encryption counterpart.
func purposeFromUse(use string) Purpose {
	if use == "enc" {
		return PurposeEncrypt
	}
	return PurposeSign
}
