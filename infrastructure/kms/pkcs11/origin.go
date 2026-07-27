//go:build !no_pkcs11

package pkcs11

import (
	"context"

	"github.com/yangwb1123/snaplink/shared/core"
)

// KeyOriginAttrs is the minimal PKCS#11 private-key-object attribute pair
// this package's KeyOrigin classification is built on: CKA_LOCAL and
// CKA_NEVER_EXTRACTABLE (PKCS#11 v2.40 Table 22, common private-key-object
// attributes). [Session.KeyOriginAttrs] reads these off the real token via
// C_GetAttributeValue (see realSession.KeyOriginAttrs, session_origin.go);
// signer_test.go's fakeSession supplies synthetic values so
// keyOriginFromAttrs is exercised without any live PKCS#11 session.
type KeyOriginAttrs struct {
	// Local mirrors CKA_LOCAL: CK_TRUE iff the key was generated ON the
	// token via C_GenerateKey/C_GenerateKeyPair, as opposed to arriving via
	// C_CreateObject or C_UnwrapKey from externally-supplied material. This
	// is the PKCS#11-standard analogue of AWS KMS DescribeKey's Origin
	// field (AwsKms/AwsCloudHsm vs External), GCP KMS's ProtectionLevel,
	// and Azure Key Vault's HsmPlatform flag: a spec-defined, token-
	// reported fact, not a guess from slot metadata.
	Local bool
	// NeverExtractable mirrors CKA_NEVER_EXTRACTABLE: CK_TRUE iff
	// CKA_EXTRACTABLE has never been CK_TRUE for this key object, i.e. the
	// private key value has never left the token's hardware boundary in
	// the clear.
	NeverExtractable bool
}

// WithKeyOrigin overrides the key origin attestation for this signer,
// pre-empting auto-detection (see KeyOrigin below). Applied once at
// construction (NewSigner), before the Signer is shared across goroutines,
// like every other Option. Use it when the operator has out-of-band
// knowledge the token's own attributes cannot capture -- e.g. a token or
// provider that does not implement CKA_LOCAL / CKA_NEVER_EXTRACTABLE at
// all, or a compliance classification that must not depend on this
// package's attribute interpretation.
func WithKeyOrigin(origin core.KeyOrigin) Option {
	return func(s *Signer) {
		s.keyOrigin = origin
		s.originLoaded = true
		s.originOverride = true
	}
}

// WithKeyID records the kid this signer's key is published under (e.g.
// cfg.KeyLabel, the same string wiring code passes as the kid to
// WithECDSAExternalSigner et al. -- see the package doc). KeyOrigin uses it
// to reject a mismatched kid the way awskms/gcpkms/azurekeyvault reject a
// kid that isn't their own keyID/keyName. Applied once at construction,
// like every other Option. Leaving it unset (the zero value) preserves the
// previous permissive behavior for callers that never told this signer its
// own kid -- there is nothing to compare against, so KeyOrigin cannot tell
// a foreign kid from its own and answers for any kid, exactly as Public()/
// Sign() also do not take a kid.
func WithKeyID(kid string) Option {
	return func(s *Signer) { s.keyID = kid }
}

// KeyOrigin implements core.KeyOriginProvider. A kid that mismatches this
// signer's own configured keyID (see WithKeyID) reports OriginUnknown
// without touching the token or the origin cache -- core.KeyOriginProvider
// is documented to answer per-kid (two keys, same issuer, different
// origins), and the three cloud-KMS peers (awskms/gcpkms/azurekeyvault)
// all reject a foreign kid the same way; this signer must not misattribute
// a query about a DIFFERENT key to its own token's origin. An explicit
// WithKeyOrigin value wins unconditionally and is never overwritten;
// otherwise the token's private-key CKA_LOCAL / CKA_NEVER_EXTRACTABLE
// attributes are queried once (via the Session) and the result is cached
// for the process lifetime -- mirroring how awskms caches DescribeKey's
// Origin, gcpkms caches ProtectionLevel, and azurekeyvault caches
// HsmPlatform, all resolved lazily on first use rather than at
// construction (construction must not touch the token).
//
// originMu is deliberately its own lock, separate from the public-key
// cache's mu: a KeyOrigin call must never block behind an in-flight
// Public()/Sign() token round-trip, and vice versa. As with mu, this is a
// mutex rather than sync.Once so a transient attribute-read error is
// retried on the next call instead of permanently poisoning the result to
// OriginUnknown (see loadPublic's identical reasoning in signer.go).
func (s *Signer) KeyOrigin(_ context.Context, kid string) (core.KeyOrigin, error) {
	if s.keyID != "" && kid != "" && kid != s.keyID {
		return core.OriginUnknown, nil
	}
	s.originMu.Lock()
	defer s.originMu.Unlock()
	if s.originLoaded {
		return s.keyOrigin, nil
	}
	attrs, err := s.sess.KeyOriginAttrs(s.keyHandle)
	if err != nil {
		// Fail-open: cannot attest. NOT cached (originLoaded stays false)
		// so the next call retries -- a transient token error must not
		// permanently poison the origin to Unknown.
		return core.OriginUnknown, nil
	}
	s.keyOrigin = keyOriginFromAttrs(attrs)
	s.originLoaded = true
	return s.keyOrigin, nil
}

// keyOriginFromAttrs is the pure attribute -> core.KeyOrigin mapping, kept
// free of any PKCS#11 session/token so it is directly unit-testable with
// synthetic inputs (see TestKeyOriginFromAttrs in signer_test.go) even in
// an environment with neither a real HSM nor a software token (SoftHSM2)
// available to exercise the live C_GetAttributeValue path.
//
//   - CKA_LOCAL false: the key material originated off-token (imported via
//     C_CreateObject or unwrapped via C_UnwrapKey) -- it was, at some
//     point, outside the hardware boundary. -> OriginImported.
//   - CKA_LOCAL true AND CKA_NEVER_EXTRACTABLE true: generated on-token
//     and never left the hardware boundary in the clear -- the strongest
//     attestation PKCS#11's standard attributes can offer. ->
//     OriginHSMGenerated.
//   - CKA_LOCAL true but NOT CKA_NEVER_EXTRACTABLE: generated on-token,
//     but CKA_EXTRACTABLE was CK_TRUE at some point (or the token does
//     not track it), so the "never left hardware" guarantee cannot be
//     attested. Report Unknown rather than overclaim OriginHSMGenerated.
func keyOriginFromAttrs(attrs KeyOriginAttrs) core.KeyOrigin {
	if !attrs.Local {
		return core.OriginImported
	}
	if attrs.NeverExtractable {
		return core.OriginHSMGenerated
	}
	return core.OriginUnknown
}

// Compile-time guard: *Signer implements core.KeyOriginProvider.
var _ core.KeyOriginProvider = (*Signer)(nil)
