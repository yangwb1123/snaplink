package redis

import (
	"context"
	"errors"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/shared/security"
)

// sso:bcl:subject:<subject> -> SET of client ids the subject has had
// active tokens issued for. ONE Redis SET per subject keeps every
// operation single-key, so the store is inherently CROSSSLOT-safe on
// Redis Cluster (no hash tag needed — a subject's whole active set is
// one key, one slot).
const subjectClientKeyPrefix = "sso:bcl:subject:"

// SubjectClientIndex is the Redis-backed implementation of
// [security.SubjectClientIndex]. Replaces the memory + sqlite backends
// for multi-replica deployments: OIDC Back-Channel Logout fan-out can
// reach every client a subject touched ACROSS the cluster, not just the
// ones whose last issuance happened to land on the replica handling the
// logout. The set is leaderless — any replica's RecordAccess is visible
// to any replica's ListClients.
//
// Mirrors the reference impls' "best-effort active set" contract: no
// TTL (neither memory nor sqlite evicts), set-membership idempotence,
// and nil-safe Forget on unknown pairs. Stale entries only cost one
// extra, harmless logout_token POST.
type SubjectClientIndex struct {
	rdb goredis.Cmdable
}

// NewSubjectClientIndex builds the store over an existing go-redis
// client.
func NewSubjectClientIndex(rdb goredis.Cmdable) *SubjectClientIndex {
	return &SubjectClientIndex{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *SubjectClientIndex) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: subject client index not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func subjectClientKey(subject string) string {
	return subjectClientKeyPrefix + subject
}

// RecordAccess marks (subject, clientID) live via SADD — a single-key
// op, so cluster-safe with no hash tag. SADD is naturally idempotent
// (re-adding an existing member is a no-op), matching the set semantics
// of the memory + sqlite references. Empty args are no-ops per the SPI.
func (s *SubjectClientIndex) RecordAccess(ctx context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return nil
	}
	if err := s.rdb.SAdd(ctx, subjectClientKey(subject), clientID).Err(); err != nil {
		return fmt.Errorf("redis: record access: %w", err)
	}
	return nil
}

// ListClients returns every client id in the subject's active set via
// SMEMBERS (single key). Order is implementation-defined per the SPI
// contract — callers treat the result as a set — so no sort. An empty
// or unknown subject yields nil, matching the memory backend.
func (s *SubjectClientIndex) ListClients(ctx context.Context, subject string) ([]string, error) {
	if subject == "" {
		return nil, nil
	}
	out, err := s.rdb.SMembers(ctx, subjectClientKey(subject)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: list clients: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Forget removes the (subject, clientID) pair via SREM (single key).
// nil-safe on unknown pairs (SREM of an absent member affects zero
// elements). Redis auto-deletes the key once its last member is
// removed, so an emptied subject leaves no tombstone — exactly the
// memory backend dropping the subject entirely.
func (s *SubjectClientIndex) Forget(ctx context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return nil
	}
	if err := s.rdb.SRem(ctx, subjectClientKey(subject), clientID).Err(); err != nil {
		return fmt.Errorf("redis: forget: %w", err)
	}
	return nil
}

var _ security.SubjectClientIndex = (*SubjectClientIndex)(nil)
