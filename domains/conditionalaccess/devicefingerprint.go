package conditionalaccess

import "context"

// DeviceFingerprint captures and looks up device-posture signals keyed by a
// caller-supplied fingerprint — a stable, per-device opaque identifier (a
// client-set device-id header/cookie, a DPoP/mTLS key thumbprint, or an
// operator's own device-inventory key). It is the conditional-access
// engine's device-posture signal source at /auth/login: the Server calls
// Lookup before building AccessContext.DevicePosture; Record lets an
// out-of-band integration (an MDM webhook, an admin enrollment API) upsert
// the posture once a device becomes known.
//
// Shape mirrors trust.TrustSignals.DeviceHints (shared/trust) — both carry
// whatever device signal the caller already has on hand, because Snaplink
// core has no device inventory of its own (see trust.DevicePostureScorer's
// doc for the same rationale) — and follows the existing SPI conventions
// (spi.RiskScorer / spi.MFAProvider, shared/spi): implementations MUST be
// safe for concurrent use (called on the /auth/login hot path) and MUST fail
// open. A Lookup error means the data source is unreachable, NOT that the
// device is untrusted — callers degrade to PostureUnknown exactly as an
// absent fingerprint does (AGENTS.md "Fail Modes"; same precedent as
// trust.TrustScorer / spi.RiskScorer). PostureUnknown is itself already
// conservative — the engine caps trust at Config.DegradedTrust for it — so
// degrading a lookup failure to Unknown is a fail-open floor, not a free
// pass.
//
// Layering: this lives beside the engine it feeds (domains/conditionalaccess)
// rather than shared/spi — the SPI's natural home — because shared/spi is at
// its frozen per-directory file-count ceiling (directory_fanout_test.go);
// shared/trust's package doc documents the identical reasoning for
// DevicePostureScorer. interfaces/sso is the only caller that needs both this
// interface and conditionalaccess.AccessContext together, and it already
// imports this package.
type DeviceFingerprint interface {
	// Lookup returns the known posture for fingerprint. ok=false means the
	// fingerprint has never been recorded (not an error — a first-seen
	// device). err != nil means the data source itself is unavailable;
	// callers MUST treat that the same as ok=false, NEVER as a signal that
	// the device is untrusted.
	Lookup(ctx context.Context, fingerprint string) (posture DevicePosture, ok bool, err error)

	// Record upserts the posture observed for fingerprint. Implementations
	// MAY leave this a no-op and rely solely on out-of-band provisioning
	// (an MDM sync job calling a different, backend-specific API). Callers
	// treat a Record error as log-only — it rides in on a request that has
	// ALREADY been decided, so it must never retroactively fail that
	// request.
	Record(ctx context.Context, fingerprint string, posture DevicePosture) error
}
