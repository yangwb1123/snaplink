package anomaly

import (
	"context"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// Detector runs OFF the request hot path on every login event
// (success or failure) and surfaces behavioral anomalies the
// synchronous [RiskScorer] can't detect: impossible travel, velocity
// surges, new device / country, brute-force horizontal sprays.
//
// Why a separate SPI from RiskScorer:
//
//   - RiskScorer is synchronous — it MUST return in milliseconds so
//     the login path doesn't stall. That budget rules out anything
//     needing windowed aggregation or per-subject baseline lookups
//     beyond a single fast key.
//   - Signal detection is inherently AFTER-THE-FACT: by the time
//     "impossible travel" is detectable, the suspicious login has
//     already returned a token. Forcing this signal into the request
//     path either causes false-positive denials (VPN users, mobile
//     IP roaming) or starves real signals (operators set thresholds
//     conservative to avoid blocking legitimate users → real attacks
//     slip through).
//   - Operators want anomalies → audit + webhook + user email, NOT
//     direct login denials. The differentiator vs synchronous risk
//     is "tell me what's unusual, let me decide policy" rather than
//     "block on every guess."
//
// Implementations get one Inspect call per LoginEvent and return zero
// or more [Signal]s. The runner emits each as an audit event +
// metric + optional webhook. Errors are logged but never propagate
// back to the login response.
//
// Detectors are stateful — they typically consult a
// [RecentLoginStore] / [KnownDeviceStore] / similar history backend.
// Implementations are responsible for their own state queries inside
// Inspect; the runner provides only ctx + the event.
type Detector interface {
	// Name is the detector identifier used in audit events + metric
	// labels (e.g. "impossible_travel", "velocity"). Stable wire
	// string.
	Name() string

	// Inspect examines the event and returns any anomalies it
	// detected. nil + no error = nothing to report. Error is
	// logged at warn level and metric'd — the runner does NOT
	// re-queue; transient backend issues (DB timeout) are accepted
	// rather than backpressured into the login path.
	Inspect(ctx context.Context, event *LoginEvent) ([]Signal, error)
}

// LoginEvent is the dispatched signal — captures everything detectors
// need without forcing them back through the audit/recorder path.
// Built at /auth/login terminus + handed to the Runner
// via a bounded queue.
type LoginEvent struct {
	// SubjectID is the user resolved by the authenticator on success,
	// or the attempted identifier (username / phone / email) on
	// failure. Detectors comparing across success+failure use this
	// as the join key; missing → detectors should skip the subject-
	// scoped checks.
	SubjectID string

	// ClientID is the registered Client.ID.
	ClientID string

	// Provider is the authenticator name ("password" / "phone" /
	// "webauthn" / "totp" / etc).
	Provider string

	// Outcome is "success" or "failure". Same vocabulary as
	// sso_login_attempts_total{outcome}.
	Outcome string

	// FailureReason is non-empty only on failure; mirrors the audit
	// Event.Reason field. Detectors classifying failure types
	// (brute-force vs credential typo) branch on this.
	FailureReason string

	// RemoteIP is the apparent client IP, extracted with the same
	// X-Forwarded-For-aware logic the audit pipeline uses.
	RemoteIP string

	// UserAgent is the raw User-Agent header. Empty when absent.
	// Detectors hashing for device fingerprint should hash on demand
	// (avoid persisting raw UA — PII-adjacent).
	UserAgent string

	// Geo is populated when [WithGeoProvider] is wired and geo
	// enrichment ran. May be nil — detectors degrade gracefully.
	// Typed as [core.GeoInfo] (aliased by geo.GeoInfo) so anomaly need
	// not import the geo package for this field.
	Geo *core.GeoInfo

	// TraceID joins the anomaly back to the originating request in
	// distributed traces (same TraceID the audit event carries).
	TraceID string

	// Timestamp is the request time, captured by the server (NOT
	// client-controlled).
	Timestamp time.Time
}

// Signal is one detector's signal that something looks unusual.
// Multiple Anomalies per LoginEvent are allowed (a single login can
// trip impossible-travel + new-country simultaneously).
type Signal struct {
	// Type is a stable wire string identifying the anomaly class
	// (e.g. "impossible_travel", "velocity_burst", "new_country").
	// Used as a metric label — keep cardinality bounded.
	Type string

	// Severity ∈ {"info", "warn", "critical"}. Drives downstream
	// routing (info → audit only; warn → audit + webhook;
	// critical → audit + webhook + user notification).
	Severity Severity

	// Score 0..100, higher = more anomalous. Detectors with a
	// natural confidence interval populate this; binary detectors
	// (new device yes/no) leave it 0.
	Score int

	// Evidence is the detector's structured rationale. Logged on
	// the audit event as metadata so operators can investigate
	// without rerunning the detection. Keep keys to a stable schema
	// per detector (e.g. impossible_travel always sets "distance_km"
	// + "elapsed_seconds" + "implied_speed_kmh").
	Evidence map[string]string

	// SubjectID is the user the anomaly applies to. Populated even
	// when LoginEvent.SubjectID was empty if the detector resolved
	// it (e.g. brute-force shadow that recognizes the attacker as
	// "scanning user X").
	SubjectID string
}

// Severity ∈ {info, warn, critical}. Wire string.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
)
