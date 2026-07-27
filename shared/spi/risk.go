package spi

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// RiskScorer evaluates an authentication attempt and returns a decision
// the SSO server acts on. Hooked into /auth/login AFTER credential
// validation but BEFORE token issuance — a Deny blocks the token, an
// Allow lets it through.
//
// Implementations are pluggable along the same SPI pattern as
// [Authenticator] and [UserProvider]: ship a noop in dev, a rule-based
// IP-allowlist / geo-gate in staging, an ML model (LSTM on access
// patterns, gradient-boosted classifier on session features, an
// upstream Bot Management API, an Anthropic-hosted risk model) in
// production. Configure with [WithRiskScorer]; absent that, no scoring
// runs and there is zero overhead on the login path.
//
// Fail-open contract: when Score returns an error, the SSO server
// logs and proceeds (treats as Allow). Failing closed on a misbehaving
// scorer locks every user out — worse than skipping a single risk
// check. Operators worried about silent bypass should alert on the
// "risk scorer failed" log line.
type RiskScorer interface {
	Score(ctx context.Context, req *RiskRequest) (*RiskAssessment, error)
}

// RiskRequest is the input to RiskScorer.Score. Fields populated from
// whatever the SSO server can observe at the login moment — additional
// signals (device fingerprint, recent failure count) should be queried
// by the scorer implementation itself from its own data store rather
// than padding this struct with optional knobs.
type RiskRequest struct {
	// SubjectID is the user id resolved by the authenticator. Always
	// present (risk is scored after successful credential validation).
	SubjectID string

	// ClientID is the registered Client.ID this attempt is for.
	ClientID string

	// Provider is the authenticator name that handled the credential
	// check (e.g. "password", "phone", "keypair"). Useful when the
	// risk policy varies by method — password attempts get scrutiny,
	// keypair / certificate get a free pass.
	Provider string

	// RemoteIP is the apparent client IP, extracted with the same
	// X-Forwarded-For-aware logic the audit pipeline uses.
	RemoteIP string

	// UserAgent is the raw User-Agent header. Empty when absent.
	UserAgent string

	// Geo is populated when [WithGeoProvider] is wired and the geo
	// middleware ran for this request. May be nil — scorers should
	// degrade gracefully. Typed as [core.GeoInfo] (aliased by geo.GeoInfo)
	// so this SPI contract does not pull the geo package into the kernel.
	Geo *core.GeoInfo

	// Timestamp is the request time, captured by the server (NOT
	// client-controlled). Stable across concurrent scorer calls for
	// the same request.
	Timestamp time.Time
}

// RiskAssessment is the output of RiskScorer.Score. Score and Tags are
// informational (logged in audit); Decision is the load-bearing field
// the SSO server acts on.
type RiskAssessment struct {
	// Score is the scorer's confidence on a 0-100 scale, higher =
	// riskier. Free for implementations to set or leave 0 when the
	// scorer is binary. Echoed into the audit event for posthoc tuning.
	Score int

	// Decision is required. Allow lets the login proceed; Deny blocks
	// it with HTTP 403 and an audit failure event; RequireMFA is
	// reserved for the future MFA orchestration layer — until it ships,
	// the server treats RequireMFA as Allow (so configuring a scorer
	// that returns it today is forward-compatible but currently a
	// no-op).
	Decision Decision

	// Reason is included in the audit Reason field on Deny. Free-form;
	// operators search on it.
	Reason string

	// Tags are structured signals the scorer attached to the decision
	// (e.g. "ip-anomaly", "off-hours", "new-device"). Reserved for
	// future structured-search audit storage.
	Tags []string
}

// Decision is the load-bearing field of [RiskAssessment]. Values are
// stable wire strings — appearing in audit events and gRPC payloads —
// so don't rename them lightly.
type Decision string

const (
	// DecisionAllow lets login proceed to token issuance. The default.
	DecisionAllow Decision = "allow"

	// DecisionRequireMFA reserves the response for future MFA orchestration.
	// Treated as Allow today (logged but does not change flow).
	DecisionRequireMFA Decision = "require_mfa"

	// DecisionDeny blocks the login with HTTP 403 and emits an audit
	// failure event with reason="risk_denied".
	DecisionDeny Decision = "deny"
)

// CertRevocationChecker reports whether an already chain-validated X.509
// certificate has been revoked (CRL, OCSP, or any operator-chosen revocation
// source). It is checked AFTER chain/expiry verification succeeds —
// revocation status is a separate signal from cryptographic validity, and
// neither crypto/x509.Verify nor crypto/tls does any revocation checking of
// its own. Without a checker wired, a compromised or revoked client
// certificate authenticates successfully via mTLS until it expires.
//
// Pluggable along the same SPI pattern as [RiskScorer]: ship no checker in
// dev (revocation checking off), a CRL-fetching implementation backed by
// the cert's CRL Distribution Points, or an OCSP-responder client, in
// production.
//
// Fail-open contract: when IsRevoked returns a non-nil error, the caller
// logs and PROCEEDS (treats the certificate as not revoked) — matching
// [RiskScorer]'s availability convention. Failing closed on a misbehaving
// or unreachable revocation source would lock out every mTLS client on an
// outage. IsRevoked returning (true, nil) is the only outcome that rejects
// the certificate.
type CertRevocationChecker interface {
	IsRevoked(ctx context.Context, cert *x509.Certificate) (bool, error)
}
