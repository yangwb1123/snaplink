// Package memory includes the in-memory [metering.Store]: per-minute
// buckets keyed by (minute, client, kind, endpoint) under a hard
// cardinality cap. When the cap is reached the OLDEST-created bucket
// is evicted — usage telemetry is a rolling operational window, not an
// archive, so bounded memory beats completeness (§5 bounded
// cardinality, same stance as the metrics layer).
package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering"
)

// DefaultMaxBuckets caps tracked buckets when WithMaxBuckets is not
// given. At one bucket per (client, kind, endpoint) per minute this
// covers hours of window for typical fleet sizes in a few hundred KB.
const DefaultMaxBuckets = 4096

type bucketKey struct {
	minute   int64
	clientID string
	kind     metering.Kind
	endpoint metering.Endpoint
}

// Store is the in-memory bounded implementation of
// [metering.Store]. Safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	max     int
	buckets map[bucketKey]int64
	// order holds keys in creation order; eviction pops the front.
	// Events arrive roughly time-ordered, so creation order ≈ oldest
	// minute — and it stays O(1) where a per-Record minute scan is not.
	order []bucketKey
}

// Option tunes the Store at construction.
type Option func(*Store)

// WithMaxBuckets overrides the tracked-bucket cap. Non-positive
// values are ignored (the default stands).
func WithMaxBuckets(n int) Option {
	return func(s *Store) {
		if n > 0 {
			s.max = n
		}
	}
}

// New returns an empty bounded Store.
func New(opts ...Option) *Store {
	s := &Store{
		max:     DefaultMaxBuckets,
		buckets: make(map[bucketKey]int64),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Record folds one event into its per-minute bucket, creating the
// bucket (and evicting the oldest when at cap) as needed.
func (s *Store) Record(_ context.Context, ev metering.Event) error {
	key := bucketKey{
		minute:   metering.BucketMinute(ev.At).Unix(),
		clientID: ev.ClientID,
		kind:     ev.Kind,
		endpoint: ev.Endpoint,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.buckets[key]; !ok {
		if len(s.buckets) >= s.max {
			s.evictOldestLocked()
		}
		s.order = append(s.order, key)
	}
	s.buckets[key]++
	return nil
}

// evictOldestLocked drops the earliest-created bucket. Caller holds mu.
func (s *Store) evictOldestLocked() {
	if len(s.order) == 0 {
		return
	}
	delete(s.buckets, s.order[0])
	s.order = s.order[1:]
}

// Query returns the buckets matching q, sorted by minute then client,
// kind, endpoint for a stable wire order.
func (s *Store) Query(_ context.Context, q metering.Query) ([]metering.Bucket, error) {
	s.mu.Lock()
	out := make([]metering.Bucket, 0)
	for key, count := range s.buckets {
		if !matches(key, q) {
			continue
		}
		out = append(out, metering.Bucket{
			Minute:   time.Unix(key.minute, 0).UTC(),
			ClientID: key.clientID,
			Kind:     key.kind,
			Endpoint: key.endpoint,
			Count:    count,
		})
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Minute.Equal(out[j].Minute) {
			return out[i].Minute.Before(out[j].Minute)
		}
		if out[i].ClientID != out[j].ClientID {
			return out[i].ClientID < out[j].ClientID
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out, nil
}

// TrackedBuckets reports current bucket cardinality (the gauge feed).
func (s *Store) TrackedBuckets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buckets)
}

func matches(key bucketKey, q metering.Query) bool {
	if q.ClientID != "" && key.clientID != q.ClientID {
		return false
	}
	if !q.Since.IsZero() && key.minute < metering.BucketMinute(q.Since).Unix() {
		return false
	}
	// Until is exclusive: a bucket AT the until minute is out.
	if !q.Until.IsZero() && key.minute >= metering.BucketMinute(q.Until).Unix() {
		return false
	}
	return true
}

var _ metering.Store = (*Store)(nil)
var _ metering.TrackedBucketReporter = (*Store)(nil)
