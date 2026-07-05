// Package cryptoinventory catalogs every piece of cryptographic key material
// the server knows about — signing keys, JWE encryption keys, KMS-backed
// keys, and (when an operator chooses to track them) mTLS trust anchors —
// behind one read model: an Entry per key, recording its id, algorithm,
// purpose, creation time, lifecycle status, and backing store.
//
// PULL, NOT DUPLICATE. Every concern in this SDK that already holds key
// material — platform/signingkeys' leaderless JWKS aggregation (via the
// issuers' own core.JWKSProvider), the corecredential-registered rotators
// platform/lifecycle/rotation drives, or a KMS-backed crypto.Signer wired at
// the composition root — remains the sole owner of that material. This
// package never stores keys or duplicates their governance metadata as a
// second source of truth. It defines a narrow Source SPI each concern
// satisfies directly, or through a small adapter (source_jwks.go,
// source_rotation.go, source_static.go), and PULLS a live snapshot on every
// ListKeys call.
//
// COMPROMISE IS BOOKKEEPING, NOT REVOCATION. ReportKeyCompromise records
// that an operator declared a key leaked — status, reason, timestamp — which
// is what an admin endpoint and an audit trail need. It is NOT the
// authoritative key-revocation mechanism: that already exists per concern
// (the signing-key issuers' RetireKey/DropVerifyKey; platform/lifecycle/
// rotation's Scheduler.Compromise for corecredential-registered classes).
// When the Source that owns a reported key also implements Retirer,
// ReportKeyCompromise best-effort triggers it; when it doesn't (a read-only
// KMS enumeration, a static trust-anchor list), the key is still recorded
// compromised for alerting/audit even though nothing was automatically
// retired.
package cryptoinventory
