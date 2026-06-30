package redis

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const consentChallengePrefix = "sso:consent:challenge:" // sso:consent:challenge:<id> -> JSON

// consentChallengeTTL mirrors consent.ChallengeTTL (5 min). Held locally so this
// nested module never imports the handler-layer consent package upward.
const (
	consentChallengeTTL       = 5 * time.Minute
	consentChallengeOpTimeout = 2 * time.Second
)

func consentChallengeKey(id string) string { return consentChallengePrefix + id }

type consentChallengeRecord struct {
	UserID               string          `json:"u"`
	ClientID             string          `json:"c"`
	Scopes               []string        `json:"s"`
	AuthorizationDetails json.RawMessage `json:"ad,omitempty"`
}

// ConsentChallengeStore is the Redis-backed, cluster-shared consent-gate
// challenge store. The in-process consent.ChallengeStore keeps the single-use
// nonce in ONE replica's memory, so on a no-affinity load balancer the approve
// POST lands on a different replica than the issue, Consume misses, and the gate
// re-issues forever — an infinite consent loop that blocks first-time
// third-party authorization. This stores the nonce in the cluster so the approve
// consumes on whatever replica handles it. One key per challenge: SET/GETDEL are
// single-key and inherently CROSSSLOT-safe. It structurally satisfies the
// interfaces/sso consent-challenge interface (matching Issue/Consume signatures)
// WITHOUT importing the handler layer.
type ConsentChallengeStore struct {
	rdb goredis.Cmdable
}

// NewConsentChallengeStore builds the store over an existing go-redis client.
func NewConsentChallengeStore(rdb goredis.Cmdable) *ConsentChallengeStore {
	return &ConsentChallengeStore{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *ConsentChallengeStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: consent challenge store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

// Issue mints a single-use challenge bound to (userID, clientID, scopes,
// authorizationDetails) under a 5-minute TTL. Best-effort write: a SET
// failure degrades to the prior per-pod re-issue behavior, never weaker.
func (s *ConsentChallengeStore) Issue(userID, clientID string, scopes []string, authorizationDetails json.RawMessage) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	if s == nil || s.rdb == nil {
		return id
	}
	rec := consentChallengeRecord{
		UserID:               userID,
		ClientID:             clientID,
		Scopes:               slices.Clone(scopes),
		AuthorizationDetails: append(json.RawMessage(nil), authorizationDetails...),
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		return id
	}
	ctx, cancel := context.WithTimeout(context.Background(), consentChallengeOpTimeout)
	defer cancel()
	_ = s.rdb.Set(ctx, consentChallengeKey(id), blob, consentChallengeTTL).Err()
	return id
}

// Consume atomically validates + removes the challenge (GETDEL = single-use,
// single-key). Returns true only if it exists (not TTL-expired), matches
// userID+clientID, scope sets, AND authorization_details bytes exactly. Any
// miss/error/decode-failure -> false (fail closed: the gate re-issues).
func (s *ConsentChallengeStore) Consume(id, userID, clientID string, scopes []string, authorizationDetails json.RawMessage) bool {
	if s == nil || s.rdb == nil || id == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), consentChallengeOpTimeout)
	defer cancel()
	blob, err := s.rdb.GetDel(ctx, consentChallengeKey(id)).Bytes()
	if err != nil {
		return false
	}
	var rec consentChallengeRecord
	if json.Unmarshal(blob, &rec) != nil {
		return false
	}
	if rec.UserID != userID || rec.ClientID != clientID || !scopesSetEqual(rec.Scopes, scopes) {
		return false
	}
	return rawJSONEqual(rec.AuthorizationDetails, authorizationDetails)
}

// rawJSONEqual reports whether two raw JSON blobs are byte-identical,
// treating nil and empty as equal (both represent "no value").
func rawJSONEqual(a, b json.RawMessage) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return bytes.Equal(a, b)
}

// scopesSetEqual is order-independent set equality, replicating consent.ScopesMatch
// (len + sorted-equal). Replicated rather than imported to keep this nested module
// from depending upward on the handler-layer consent package.
func scopesSetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := slices.Clone(a)
	bs := slices.Clone(b)
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}
