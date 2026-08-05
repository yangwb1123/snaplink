package redis

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
	"golang.org/x/crypto/bcrypt"
)

// Key layout. The client JSON lives at one key per id; a global SET indexes
// every id so List() (which a stateless deployment still needs for the admin
// console + discovery projection) works without a SCAN.
const (
	clientKeyPrefix    = "sso:client:"          // sso:client:<id> -> JSON
	clientAllKey       = "sso:client:all"       // SET of every client id
	clientTenantPrefix = "sso:client:bytenant:" // SET of client ids per tenant ("" tenant included)
)

func clientTenantKey(tenantID string) string { return clientTenantPrefix + tenantID }

// ClientStore is the Redis-backed [sso.ClientStore]. Unlike the ephemeral
// single-use stores in this module, clients are durable — this is the scale
// peer for the hot-path clientStore.Get every /auth/login and /token perform,
// so a multi-replica fleet shares one client registry instead of each replica
// holding its own embedded SQLite/memory copy.
//
// Secrets and RFC 7592 registration tokens are bcrypt-hashed at rest on
// Add/Update/RotateSecret, matching the memory + SQLite peers; ValidateSecret
// routes through security.CompareClientSecret so a pre-hashed seed and a
// plaintext legacy value both compare in constant time.
//
// ClientStoreStats and TenantScopedClientStore are implemented: a
// per-tenant SET index (maintained on the write paths) serves ListByTenant,
// and Stats materializes the set once (one pipelined read) for the
// discovery-doc cache's fingerprint decision — the memory/SQLite peers'
// shape. The server therefore never falls back to List()-and-filter or a
// silent no-op tenant revocation over Redis.
type ClientStore struct {
	rdb goredis.Cmdable
}

// NewClientStore builds a ClientStore over an existing go-redis client (or
// cluster client — any goredis.Cmdable). The caller owns the client lifecycle.
func NewClientStore(rdb goredis.Cmdable) *ClientStore {
	return &ClientStore{rdb: rdb}
}

// Ping reports Redis connection health for [sso.WithReadyCheck] wiring.
func (s *ClientStore) Ping(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}

func clientKey(id string) string { return clientKeyPrefix + id }

// storedClient is the Redis record shape. sso.Client.Secret and
// RegistrationAccessToken are json:"-" (excluded so they never leak through
// API/discovery serialization), so marshaling the struct alone would silently
// drop them. The wrapper carries them in explicit fields — the same problem
// the SQLite peer solves with dedicated columns.
type storedClient struct {
	Client          *sso.Client `json:"client"`
	Secret          string      `json:"secret,omitempty"`
	PreviousSecret  string      `json:"previous_secret,omitempty"`
	SecretRotatedAt time.Time   `json:"secret_rotated_at,omitempty"`
	OverlapUntil    time.Time   `json:"secret_overlap_until,omitempty"`
	SecretExpiresAt time.Time   `json:"secret_expires_at,omitempty"`
	RegToken        string      `json:"reg_token,omitempty"`
	PreviousReg     string      `json:"previous_reg_token,omitempty"`
	RegOverlapUntil time.Time   `json:"reg_overlap_until,omitempty"`
}

func marshalClient(c *sso.Client) ([]byte, error) {
	return json.Marshal(storedClient{
		Client: c, Secret: c.Secret, PreviousSecret: c.PreviousSecret,
		SecretRotatedAt: c.SecretRotatedAt, OverlapUntil: c.SecretOverlapUntil,
		SecretExpiresAt: c.SecretExpiresAt,
		RegToken:        c.RegistrationAccessToken, PreviousReg: c.PreviousRegistrationAccessToken,
		RegOverlapUntil: c.RegistrationAccessTokenOverlapUntil,
	})
}

func unmarshalClient(raw []byte) (*sso.Client, error) {
	var sc storedClient
	if err := json.Unmarshal(raw, &sc); err != nil {
		return nil, err
	}
	if sc.Client == nil {
		return nil, errors.New("redis: nil client in stored record")
	}
	sc.Client.Secret = sc.Secret
	sc.Client.PreviousSecret = sc.PreviousSecret
	sc.Client.SecretRotatedAt = sc.SecretRotatedAt
	sc.Client.SecretOverlapUntil = sc.OverlapUntil
	sc.Client.SecretExpiresAt = sc.SecretExpiresAt
	sc.Client.RegistrationAccessToken = sc.RegToken
	sc.Client.PreviousRegistrationAccessToken = sc.PreviousReg
	sc.Client.RegistrationAccessTokenOverlapUntil = sc.RegOverlapUntil
	return sc.Client, nil
}

func (s *ClientStore) Get(ctx context.Context, clientID string) (*sso.Client, error) {
	raw, err := s.rdb.Get(ctx, clientKey(clientID)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, sso.ErrNoSuchClient
	}
	if err != nil {
		return nil, fmt.Errorf("redis: get client: %w", err)
	}
	c, err := unmarshalClient(raw)
	if err != nil {
		return nil, fmt.Errorf("redis: decode client: %w", err)
	}
	return c, nil
}

func (s *ClientStore) ValidateSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := s.Get(ctx, clientID)
	if err != nil {
		return err
	}
	current := security.CompareClientSecret(c.Secret, clientSecret)
	previous := time.Now().Before(c.SecretOverlapUntil) && security.CompareClientSecret(c.PreviousSecret, clientSecret)
	if !current && !previous {
		return errors.New("redis: invalid client secret")
	}
	if !c.SecretExpiresAt.IsZero() && !time.Now().Before(c.SecretExpiresAt) {
		return errors.New("redis: client secret expired")
	}
	if !c.Active {
		return errors.New("redis: client is inactive")
	}
	return nil
}

func (s *ClientStore) List(ctx context.Context) ([]*sso.Client, error) {
	ids, err := s.rdb.SMembers(ctx, clientAllKey).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: list client ids: %w", err)
	}
	if len(ids) == 0 {
		return []*sso.Client{}, nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = clientKey(id)
	}
	// Per-key GET pipeline, not MGET: client keys span every hash slot, so a
	// single MGET is a CROSSSLOT error on a real cluster. mgetCompat returns
	// the same positional []any (nil for misses) so the loop below is unchanged.
	vals, err := mgetCompat(ctx, s.rdb, keys)
	if err != nil {
		return nil, fmt.Errorf("redis: mget clients: %w", err)
	}
	out := make([]*sso.Client, 0, len(vals))
	for _, v := range vals {
		// A nil entry is an orphan index id whose JSON key expired/was
		// removed out of band — skip rather than fail the whole list.
		str, ok := v.(string)
		if !ok {
			continue
		}
		c, err := unmarshalClient([]byte(str))
		if err != nil {
			return nil, fmt.Errorf("redis: decode client in list: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *ClientStore) Add(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("redis: client.ID required")
	}
	if err := hashClientSecrets(c); err != nil {
		return err
	}
	if c.Secret != "" {
		now := time.Now()
		c.SecretRotatedAt = now
		if c.SecretExpiresAt.IsZero() {
			c.SecretExpiresAt = now.Add(clientrotation.DefaultLifetime)
		}
	}
	raw, err := marshalClient(c)
	if err != nil {
		return fmt.Errorf("redis: encode client: %w", err)
	}
	// SetNX is the atomic existence gate — only the first writer for an id
	// wins, so a concurrent double-create maps to ErrClientExists exactly once.
	ok, err := s.rdb.SetNX(ctx, clientKey(c.ID), raw, 0).Result()
	if err != nil {
		return fmt.Errorf("redis: add client: %w", err)
	}
	if !ok {
		return sso.ErrClientExists
	}
	if err := s.rdb.SAdd(ctx, clientAllKey, c.ID).Err(); err != nil {
		return fmt.Errorf("redis: index client: %w", err)
	}
	// Tenant index: same best-effort style as clientAllKey (a failure leaves
	// an orphan id that readers skip).
	if err := s.rdb.SAdd(ctx, clientTenantKey(c.TenantID), c.ID).Err(); err != nil {
		return fmt.Errorf("redis: index client tenant: %w", err)
	}
	return nil
}

func (s *ClientStore) Update(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("redis: client.ID required")
	}
	oldRaw, err := s.rdb.Get(ctx, clientKey(c.ID)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return sso.ErrNoSuchClient
	}
	if err != nil {
		return fmt.Errorf("redis: check client: %w", err)
	}
	oldTenant := ""
	if old, uerr := unmarshalClient(oldRaw); uerr == nil {
		oldTenant = old.TenantID
	}
	if err := hashClientSecrets(c); err != nil {
		return err
	}
	raw, err := marshalClient(c)
	if err != nil {
		return fmt.Errorf("redis: encode client: %w", err)
	}
	if err := s.rdb.Set(ctx, clientKey(c.ID), raw, 0).Err(); err != nil {
		return fmt.Errorf("redis: update client: %w", err)
	}
	// Keep the indexes consistent (idempotent) in case they drifted: the
	// all-clients set, plus the tenant set when the binding moved.
	if oldTenant != c.TenantID {
		if err := s.rdb.SRem(ctx, clientTenantKey(oldTenant), c.ID).Err(); err != nil {
			return fmt.Errorf("redis: unindex client tenant: %w", err)
		}
		if err := s.rdb.SAdd(ctx, clientTenantKey(c.TenantID), c.ID).Err(); err != nil {
			return fmt.Errorf("redis: index client tenant: %w", err)
		}
	}
	return s.rdb.SAdd(ctx, clientAllKey, c.ID).Err()
}

func (s *ClientStore) Delete(ctx context.Context, clientID string) error {
	// Idempotent: missing ids return nil so reconciliation loops don't churn.
	oldTenant := ""
	if oldRaw, gerr := s.rdb.Get(ctx, clientKey(clientID)).Bytes(); gerr == nil {
		if old, uerr := unmarshalClient(oldRaw); uerr == nil {
			oldTenant = old.TenantID
		}
	}
	if err := s.rdb.Del(ctx, clientKey(clientID)).Err(); err != nil {
		return fmt.Errorf("redis: delete client: %w", err)
	}
	if err := s.rdb.SRem(ctx, clientAllKey, clientID).Err(); err != nil {
		return fmt.Errorf("redis: unindex client: %w", err)
	}
	return s.rdb.SRem(ctx, clientTenantKey(oldTenant), clientID).Err()
}

func (s *ClientStore) RotateSecret(ctx context.Context, clientID string) (string, error) {
	return s.RotateSecretWithLifecycle(ctx, clientID, 0, clientrotation.DefaultLifetime)
}

func (s *ClientStore) RotateSecretWithOverlap(ctx context.Context, clientID string, overlap time.Duration) (string, error) {
	return s.RotateSecretWithLifecycle(ctx, clientID, overlap, clientrotation.DefaultLifetime)
}

func (s *ClientStore) RotateSecretWithLifecycle(ctx context.Context, clientID string, overlap, lifetime time.Duration) (string, error) {
	plaintext, err := generateSecret(32)
	if err != nil {
		return "", err
	}
	hashed, err := bcryptHash(plaintext)
	if err != nil {
		return "", fmt.Errorf("redis: hash rotated secret: %w", err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		oldRaw, err := s.rdb.Get(ctx, clientKey(clientID)).Bytes()
		if errors.Is(err, goredis.Nil) {
			return "", sso.ErrNoSuchClient
		}
		if err != nil {
			return "", fmt.Errorf("redis: get client for rotation: %w", err)
		}
		newRaw, err := rotatedClientRecord(oldRaw, hashed, overlap, lifetime)
		if err != nil {
			return "", err
		}
		swapped, err := s.swapClientRecord(ctx, clientID, oldRaw, newRaw)
		if err != nil {
			return "", err
		}
		if swapped {
			return plaintext, nil
		}
	}
	return "", errors.New("redis: concurrent client secret rotations did not converge")
}

func rotatedClientRecord(raw []byte, hashed string, overlap, lifetime time.Duration) ([]byte, error) {
	c, err := unmarshalClient(raw)
	if err != nil {
		return nil, fmt.Errorf("redis: decode client for rotation: %w", err)
	}
	now := time.Now()
	c.PreviousSecret = ""
	c.SecretOverlapUntil = time.Time{}
	if overlap > 0 && c.Secret != "" {
		c.PreviousSecret = c.Secret
		c.SecretOverlapUntil = now.Add(overlap)
	}
	c.Secret = hashed
	c.SecretRotatedAt = now
	c.SecretExpiresAt = clientrotation.ExpiresAt(now, lifetime)
	encoded, err := marshalClient(c)
	if err != nil {
		return nil, fmt.Errorf("redis: encode client: %w", err)
	}
	return encoded, nil
}

func (s *ClientStore) swapClientRecord(ctx context.Context, id string, oldRaw, newRaw []byte) (bool, error) {
	const script = `
local current = redis.call('GET', KEYS[1])
if not current then return -1 end
if current ~= ARGV[1] then return 0 end
redis.call('SET', KEYS[1], ARGV[2])
return 1`
	result, err := s.rdb.Eval(ctx, script, []string{clientKey(id)}, oldRaw, newRaw).Int64()
	if err != nil {
		return false, fmt.Errorf("redis: persist rotated secret: %w", err)
	}
	if result < 0 {
		return false, sso.ErrNoSuchClient
	}
	return result == 1, nil
}

// ListByTenant satisfies sso.TenantScopedClientStore: returns every client
// whose TenantID matches, via the per-tenant SET index. Empty tenantID
// returns the tenant-less bucket. Orphan index ids (record deleted out of
// band) are skipped like List does.
func (s *ClientStore) ListByTenant(ctx context.Context, tenantID string) ([]*sso.Client, error) {
	ids, err := s.rdb.SMembers(ctx, clientTenantKey(tenantID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: list tenant client ids: %w", err)
	}
	if len(ids) == 0 {
		return []*sso.Client{}, nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = clientKey(id)
	}
	vals, err := mgetCompat(ctx, s.rdb, keys)
	if err != nil {
		return nil, fmt.Errorf("redis: mget tenant clients: %w", err)
	}
	out := make([]*sso.Client, 0, len(vals))
	for _, v := range vals {
		str, ok := v.(string)
		if !ok {
			continue
		}
		c, err := unmarshalClient([]byte(str))
		if err != nil {
			return nil, fmt.Errorf("redis: decode tenant client: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

// Stats satisfies core.ClientStoreStats with the memory/SQLite peers'
// shape: materialize the set once and fingerprint it with the canonical
// core.ClientSetFingerprint. The discovery-doc cache uses the hash to skip
// its re-projection when nothing discovery-relevant changed.
func (s *ClientStore) Stats(ctx context.Context) (int, string, error) {
	clients, err := s.List(ctx)
	if err != nil {
		return 0, "", err
	}
	return len(clients), core.ClientSetFingerprint(clients), nil
}

var (
	_ sso.ClientStore             = (*ClientStore)(nil)
	_ sso.TenantScopedClientStore = (*ClientStore)(nil)
	_ core.ClientStoreStats       = (*ClientStore)(nil)
)

func (s *ClientStore) ListDueForRotation(ctx context.Context, olderThan time.Time) ([]string, error) {
	clients, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, c := range clients {
		if c.Active && c.Secret != "" && !c.SecretRotatedAt.IsZero() && !c.SecretRotatedAt.After(olderThan) {
			ids = append(ids, c.ID)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// hashClientSecrets bcrypt-hashes the Secret + RegistrationAccessToken in place
// when they are still plaintext, matching the memory + SQLite peers' hash-at-
// rest guarantee. Already-hashed ($2 prefix) values pass through untouched so
// re-Update is idempotent.
func hashClientSecrets(c *sso.Client) error {
	if c.Secret != "" && !isBcryptHash(c.Secret) {
		h, err := bcryptHash(c.Secret)
		if err != nil {
			return fmt.Errorf("redis: hash secret: %w", err)
		}
		c.Secret = h
	}
	if c.RegistrationAccessToken != "" && !isBcryptHash(c.RegistrationAccessToken) {
		h, err := bcryptHash(c.RegistrationAccessToken)
		if err != nil {
			return fmt.Errorf("redis: hash registration token: %w", err)
		}
		c.RegistrationAccessToken = h
	}
	if c.PreviousSecret != "" && !isBcryptHash(c.PreviousSecret) {
		h, err := bcryptHash(c.PreviousSecret)
		if err != nil {
			return fmt.Errorf("redis: hash previous secret: %w", err)
		}
		c.PreviousSecret = h
	}
	if c.PreviousRegistrationAccessToken != "" && !isBcryptHash(c.PreviousRegistrationAccessToken) {
		h, err := bcryptHash(c.PreviousRegistrationAccessToken)
		if err != nil {
			return fmt.Errorf("redis: hash previous registration token: %w", err)
		}
		c.PreviousRegistrationAccessToken = h
	}
	return nil
}

func isBcryptHash(s string) bool { return strings.HasPrefix(s, "$2") }

func bcryptHash(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// generateSecret returns a base64url-encoded random string (n bytes of
// entropy). 32 bytes ~= 256 bits — matches the memory peer.
func generateSecret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("redis: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

var (
	_ sso.ClientStore                             = (*ClientStore)(nil)
	_ clientrotation.ClientRotationLister         = (*ClientStore)(nil)
	_ clientrotation.ClientSecretOverlapRotator   = (*ClientStore)(nil)
	_ clientrotation.ClientSecretLifecycleRotator = (*ClientStore)(nil)
)
