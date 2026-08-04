// Package detect implements anomaly detectors that inspect login events
// and produce signals for the anomaly runner.
package detect

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/domains/anomaly/fingerprint"
	"github.com/yangwb1123/snaplink/domains/anomaly/signature"
)

// FeatureAggregator is a Detector that records device fingerprint and
// IP/geo signatures into a SignatureStore for other detectors to query.
// It returns no signals of its own — its role is data aggregation.
type FeatureAggregator struct {
	store signature.Store
}

// NewFeatureAggregator creates a FeatureAggregator.
func NewFeatureAggregator(store signature.Store) *FeatureAggregator {
	return &FeatureAggregator{store: store}
}

func (f *FeatureAggregator) Name() string { return "feature_aggregator" }

// Inspect records device fingerprint and IP/geo signatures.
func (f *FeatureAggregator) Inspect(ctx context.Context, event *anomaly.LoginEvent) ([]anomaly.Signal, error) {
	if fp := deviceFingerprint(event); fp != "" {
		if err := f.store.Record(ctx, signature.Entry{
			Signature: fp,
			SubjectID: event.SubjectID,
			Outcome:   event.Outcome,
			Timestamp: event.Timestamp,
		}); err != nil {
			return nil, err
		}
	}
	if ipSig := ipSignature(event); ipSig != "" {
		if err := f.store.Record(ctx, signature.Entry{
			Signature: ipSig,
			SubjectID: event.SubjectID,
			Outcome:   event.Outcome,
			Timestamp: event.Timestamp,
		}); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func deviceFingerprint(event *anomaly.LoginEvent) string {
	if event.UserAgent == "" {
		return ""
	}
	return fingerprint.Derive(&fingerprint.Input{UserAgent: event.UserAgent})
}

func ipSignature(event *anomaly.LoginEvent) string {
	if event.RemoteIP == "" {
		return ""
	}
	if event.Geo != nil && event.Geo.CountryCode != "" {
		sig := "geo:" + event.Geo.CountryCode
		if event.Geo.Region != "" {
			sig += "_" + event.Geo.Region
		}
		return sig
	}
	return "ip:" + sha256Hex(event.RemoteIP)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}
