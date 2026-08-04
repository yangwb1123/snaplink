// Package signature provides a SPI and in-memory implementation for
// storing and querying login signatures (device fingerprint hashes,
// geo identifiers, etc.) used by anomaly detectors.
package signature

import (
	"context"
	"time"
)

// Entry represents one observed login signature.
type Entry struct {
	Signature string
	SubjectID string
	Outcome   string
	Timestamp time.Time
}

// Store persists login signatures for new-device, new-country, and
// credential-stuffing detectors. Thread-safe implementations required.
type Store interface {
	Record(ctx context.Context, entry Entry) error

	// Seen returns true if signature was recorded within [since, now).
	// Empty subjectID matches any subject.
	Seen(ctx context.Context, signature string, since time.Time, subjectID string) (bool, error)

	// DistinctCount returns the number of distinct signatures matching
	// signaturePrefix within the time window. Empty prefix = all.
	DistinctCount(ctx context.Context, signaturePrefix string, since time.Time) (int, error)

	PruneOlder(ctx context.Context, cutoff time.Time) (int64, error)
}
