// Package tokenusage provides the token-usage telemetry SPI — the
// aggregation layer between "a token was issued/presented" and the
// operator question "which clients are using which tokens, how much,
// where?" that raw audit events cannot answer at scale.
//
// Events are OFF the request hot path by design: handlers Offer events
// to a bounded [Recorder] which drains asynchronously into a [Store]
// (mirrors how domains/anomaly stays off-path). A full queue DROPS the
// event and bumps a metric — usage telemetry must never add latency or
// failure modes to /token or /token/introspect.
//
// Privacy: an [Event] never carries the token value. The only token
// identifier is Thumbprint — the SHA-256 of the token's jti — so the
// store cannot become a new bearer-credential leak surface. The only
// PII is the subject id.
package metering

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Kind is the token category a usage event concerns. Bounded set —
// it becomes a metric label and a bucket dimension.
type Kind string

const (
	// KindAccess is an OAuth 2.0 access token.
	KindAccess Kind = "access"
	// KindRefresh is an OAuth 2.0 refresh token.
	KindRefresh Kind = "refresh"
	// KindID is an OIDC ID token.
	KindID Kind = "id"
)

// Endpoint is where the usage was observed. Bounded set — it becomes
// a metric label and a bucket dimension.
type Endpoint string

const (
	// EndpointToken marks issuance events. All issuance seams fold
	// into this one value (including the /auth/login initial mint) to
	// keep the endpoint dimension bounded.
	EndpointToken Endpoint = "token"
	// EndpointIntrospect marks RFC 7662 introspection of an ACTIVE token.
	EndpointIntrospect Endpoint = "introspect"
	// EndpointUserinfo marks /userinfo presentations.
	EndpointUserinfo Endpoint = "userinfo"
)

// Event is one token-usage observation. It carries only coarse,
// bounded fields: the token thumbprint (never the token), the token
// kind, the client + subject + tenant identifiers, the observing
// endpoint, a timestamp, and an optional coarse geo hint.
type Event struct {
	// Thumbprint is the hex SHA-256 of the token's jti claim — NEVER
	// the token value. Empty when the observing seam does not know
	// the jti (e.g. issuance, where the jti is minted inside the
	// TokenIssuer); aggregation does not depend on it.
	Thumbprint string
	Kind       Kind
	Endpoint   Endpoint
	ClientID   string
	// SubjectID is the subject identifier — the only PII an Event
	// may carry.
	SubjectID string
	TenantID  string
	// At is when the usage was observed; the store buckets it to the
	// UTC minute. Zero ⇒ the Recorder stamps time.Now at Offer.
	At time.Time
	// GeoCountry is the optional coarse geo hint (ISO 3166-1 alpha-2
	// country code). Never finer-grained — city/lat/lon would turn
	// the usage store into a location-tracking surface.
	GeoCountry string
}

// Bucket is one aggregated per-minute count for a
// (client, kind, endpoint) combination.
type Bucket struct {
	Minute   time.Time `json:"minute"`
	ClientID string    `json:"client_id"`
	Kind     Kind      `json:"kind"`
	Endpoint Endpoint  `json:"endpoint"`
	Count    int64     `json:"count"`
}

// Query filters aggregated buckets. Zero-value fields are unbounded:
// empty ClientID matches every client; zero Since/Until leave the
// window open on that side. Until is EXCLUSIVE (half-open window,
// [Since, Until)) so adjacent windows never double-count a minute.
type Query struct {
	ClientID string
	Since    time.Time
	Until    time.Time
}

// Store persists token-usage telemetry. Record ingests one raw event
// (implementations aggregate into per-minute buckets); Query returns
// the aggregated buckets. Implementations MUST be safe for concurrent
// use — the Recorder drains on a background goroutine while the admin
// read API queries.
type Store interface {
	Record(ctx context.Context, ev Event) error
	Query(ctx context.Context, q Query) ([]Bucket, error)
}

// TrackedBucketReporter is an OPTIONAL Store extension reporting how
// many buckets are currently tracked. The Recorder uses it to feed the
// tracked-bucket gauge so operators can watch a bounded store approach
// its eviction cap.
type TrackedBucketReporter interface {
	TrackedBuckets() int
}

// Thumbprint returns the hex SHA-256 digest of a token's jti claim,
// or "" for an empty jti. Hashing (rather than storing the jti raw)
// keeps the usage store useless for correlating against revocation
// lists or logs that carry raw jtis, without losing per-token
// distinctness.
func Thumbprint(jti string) string {
	if jti == "" {
		return ""
	}
	h := sha256.Sum256([]byte(jti))
	return hex.EncodeToString(h[:])
}

// BucketMinute truncates t to its UTC minute — the canonical bucket
// boundary every Store implementation must use so buckets from
// different replicas line up.
func BucketMinute(t time.Time) time.Time {
	return t.UTC().Truncate(time.Minute)
}
