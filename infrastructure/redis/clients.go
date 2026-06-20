package redis

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/security"
	"golang.org/x/crypto/bcrypt"
)

// Key layout. The client JSON lives at one key per id; a global SET indexes
// every id so List() (which a stateless deployment still needs for the admin
// console + discovery projection) works without a SCAN.
const (
	clientKeyPrefix = "sso:client:"    // sso:client:<id> -> JSON
	clientAllKey    = "sso:client:all" // SET of every client id
)

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
// The optional ClientStoreStats and TenantScopedClientStore extensions are
// intentionally not implemented: the server falls back to List()-and-filter
// for tenant scoping and to a full discovery re-projection without Stats, both
// of which are correct (just unoptimized) over Redis.
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
	Client   *sso.Client `json:"client"`
	Secret   string      `json:"secret,omitempty"`
	RegToken string      `json:"reg_token,omitempty"`
}

func marshalClient(c *sso.Client) ([]byte, error) {
	return json.Marshal(storedClient{Client: c, Secret: c.Secret, RegToken: c.RegistrationAccessToken})
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
	sc.Client.RegistrationAccessToken = sc.RegToken
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
	if !security.CompareClientSecret(c.Secret, clientSecret) {
		return errors.New("redis: invalid client secret")
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
	vals, err := s.rdb.MGet(ctx, keys...).Result()
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
	return nil
}

func (s *ClientStore) Update(ctx context.Context, c *sso.Client) error {
	if c == nil || c.ID == "" {
		return errors.New("redis: client.ID required")
	}
	exists, err := s.rdb.Exists(ctx, clientKey(c.ID)).Result()
	if err != nil {
		return fmt.Errorf("redis: check client: %w", err)
	}
	if exists == 0 {
		return sso.ErrNoSuchClient
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
	// Keep the index consistent (idempotent) in case it drifted.
	return s.rdb.SAdd(ctx, clientAllKey, c.ID).Err()
}

func (s *ClientStore) Delete(ctx context.Context, clientID string) error {
	// Idempotent: missing ids return nil so reconciliation loops don't churn.
	if err := s.rdb.Del(ctx, clientKey(clientID)).Err(); err != nil {
		return fmt.Errorf("redis: delete client: %w", err)
	}
	return s.rdb.SRem(ctx, clientAllKey, clientID).Err()
}

func (s *ClientStore) RotateSecret(ctx context.Context, clientID string) (string, error) {
	c, err := s.Get(ctx, clientID)
	if err != nil {
		return "", err
	}
	plaintext, err := generateSecret(32)
	if err != nil {
		return "", err
	}
	hashed, err := bcryptHash(plaintext)
	if err != nil {
		return "", fmt.Errorf("redis: hash rotated secret: %w", err)
	}
	// Store the hash; return the plaintext (one-time reveal). c.Secret is
	// already a hash from the prior write — overwrite it directly without
	// re-running hashClientSecrets (which would no-op on the bcrypt prefix).
	c.Secret = hashed
	raw, err := marshalClient(c)
	if err != nil {
		return "", fmt.Errorf("redis: encode client: %w", err)
	}
	if err := s.rdb.Set(ctx, clientKey(clientID), raw, 0).Err(); err != nil {
		return "", fmt.Errorf("redis: persist rotated secret: %w", err)
	}
	return plaintext, nil
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

var _ sso.ClientStore = (*ClientStore)(nil)
