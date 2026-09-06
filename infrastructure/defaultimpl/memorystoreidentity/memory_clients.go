package memorystoreidentity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is mutable so high-volume tests can use bcrypt.MinCost.
var BcryptCost = bcrypt.DefaultCost

func hashClientSecret(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), BcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func isBcryptHash(value string) bool {
	return strings.HasPrefix(value, "$2")
}

func compareClientSecret(stored, plaintext string) bool {
	return security.CompareClientSecret(stored, plaintext)
}

// MemoryClientStore stores client applications in memory. Implements the full
// core.ClientStore including the admin extensions (List/Update/Delete/Rotate).
type MemoryClientStore struct {
	mu      sync.RWMutex
	clients map[string]*core.Client
}

func NewMemoryClientStore() *MemoryClientStore {
	return &MemoryClientStore{clients: make(map[string]*core.Client)}
}

// AddSeed inserts a client without the duplicate-check that Add enforces.
// Used by the YAML loader to populate the store at boot — duplicates in the
// config file should fail explicitly via validation, not collide here.
// Hashes the plaintext Secret and RegistrationAccessToken at insertion so the
// in-memory store has the same hash-at-rest guarantees as the SQLite backend.
func (m *MemoryClientStore) AddSeed(client *core.Client) {
	if client.Secret != "" && !isBcryptHash(client.Secret) {
		if h, err := hashClientSecret(client.Secret); err == nil {
			client.Secret = h
		}
	}
	if client.PreviousSecret != "" && !isBcryptHash(client.PreviousSecret) {
		if h, err := hashClientSecret(client.PreviousSecret); err == nil {
			client.PreviousSecret = h
		}
	}
	if client.RegistrationAccessToken != "" && !isBcryptHash(client.RegistrationAccessToken) {
		if h, err := hashClientSecret(client.RegistrationAccessToken); err == nil {
			client.RegistrationAccessToken = h
		}
	}
	m.mu.Lock()
	m.clients[client.ID] = cloneClient(client)
	m.mu.Unlock()
}

func (m *MemoryClientStore) Get(_ context.Context, clientID string) (*core.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.clients[clientID]
	if !ok {
		return nil, core.ErrNoSuchClient
	}
	return cloneClient(c), nil
}

func (m *MemoryClientStore) ValidateSecret(_ context.Context, clientID, clientSecret string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.clients[clientID]
	if !ok {
		return core.ErrNoSuchClient
	}
	// A client with NO stored secret must never authenticate — not even
	// against an empty presented value. An empty stored secret is exactly
	// the fresh-node-restore state (snapshot artifacts never carry
	// secrets); accepting ("","") here would let anyone who knows only a
	// client_id authenticate as a confidential client (RFC 6749 §2.3.1) at
	// every credential endpoint that reaches ValidateSecret. The FAPI
	// client-auth method gate runs before credential validation, so an
	// enforce-mode Basic violation still reports invalid_request.
	if c.Secret == "" {
		return fmt.Errorf("client has no secret configured")
	}
	// compareClientSecret uses bcrypt.CompareHashAndPassword when the stored
	// value starts with "$2" (a bcrypt hash), falling back to constant-time
	// string compare for plaintext secrets in pre-migration / hand-authored
	// stores.
	current := compareClientSecret(c.Secret, clientSecret)
	previous := time.Now().Before(c.SecretOverlapUntil) && compareClientSecret(c.PreviousSecret, clientSecret)
	if !current && !previous {
		return fmt.Errorf("invalid client secret")
	}
	if !c.SecretExpiresAt.IsZero() && !time.Now().Before(c.SecretExpiresAt) {
		return fmt.Errorf("client secret expired")
	}
	if !c.Active {
		return fmt.Errorf("client is inactive")
	}
	return nil
}

func (m *MemoryClientStore) List(_ context.Context) ([]*core.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*core.Client, 0, len(m.clients))
	for _, c := range m.clients {
		out = append(out, cloneClient(c))
	}
	return out, nil
}

// ListByTenant satisfies core.TenantScopedClientStore: returns
// every client whose TenantID matches. Empty tenantID returns
// every client whose TenantID is also empty (the "no-tenant"
// bucket — useful for single-tenant deployments and the
// platform-admin client).
func (m *MemoryClientStore) ListByTenant(_ context.Context, tenantID string) ([]*core.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*core.Client
	for _, c := range m.clients {
		if c.TenantID == tenantID {
			out = append(out, cloneClient(c))
		}
	}
	return out, nil
}

// Stats satisfies core.ClientStoreStats: a cheap, order-independent
// fingerprint of the client set so the discovery-doc cache can skip its
// full List() + re-projection when nothing discovery-relevant changed.
// The map snapshot under RLock is the only allocation; the digest is
// pure CPU. The hash covers exactly the fields the discovery document
// derives from a client (see core.ClientSetFingerprint), so a scope
// edit or a new client flips it while a secret rotation does not.
func (m *MemoryClientStore) Stats(_ context.Context) (int, string, error) {
	m.mu.RLock()
	clients := make([]*core.Client, 0, len(m.clients))
	for _, c := range m.clients {
		clients = append(clients, cloneClient(c))
	}
	m.mu.RUnlock()
	return len(clients), core.ClientSetFingerprint(clients), nil
}

func (m *MemoryClientStore) Add(_ context.Context, c *core.Client) error {
	if c == nil || c.ID == "" {
		return fmt.Errorf("defaultimpl: client.ID required")
	}
	if c.Secret != "" && !isBcryptHash(c.Secret) {
		h, err := hashClientSecret(c.Secret)
		if err != nil {
			return fmt.Errorf("defaultimpl: hash secret: %w", err)
		}
		c.Secret = h
	}
	if c.RegistrationAccessToken != "" && !isBcryptHash(c.RegistrationAccessToken) {
		h, err := hashClientSecret(c.RegistrationAccessToken)
		if err != nil {
			return fmt.Errorf("defaultimpl: hash registration token: %w", err)
		}
		c.RegistrationAccessToken = h
	}
	if c.PreviousSecret != "" && !isBcryptHash(c.PreviousSecret) {
		h, err := hashClientSecret(c.PreviousSecret)
		if err != nil {
			return fmt.Errorf("defaultimpl: hash previous secret: %w", err)
		}
		c.PreviousSecret = h
	}
	// SecretRotatedAt baselines at creation time so a freshly-added
	// confidential client is immediately eligible for scheduled rotation
	// once it ages past the configured interval — see ListDueForRotation.
	// A secretless client (federation-derived / public) has nothing to
	// rotate, so its timestamp stays zero (never due).
	if c.Secret != "" {
		now := time.Now()
		c.SecretRotatedAt = now
		if c.SecretExpiresAt.IsZero() {
			c.SecretExpiresAt = now.Add(clientrotation.DefaultLifetime)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.clients[c.ID]; exists {
		return core.ErrClientExists
	}
	m.clients[c.ID] = cloneClient(c)
	return nil
}

func (m *MemoryClientStore) Update(_ context.Context, c *core.Client) error {
	if c == nil || c.ID == "" {
		return fmt.Errorf("defaultimpl: client.ID required")
	}
	if c.Secret != "" && !isBcryptHash(c.Secret) {
		h, err := hashClientSecret(c.Secret)
		if err != nil {
			return fmt.Errorf("defaultimpl: hash secret: %w", err)
		}
		c.Secret = h
	}
	if c.RegistrationAccessToken != "" && !isBcryptHash(c.RegistrationAccessToken) {
		h, err := hashClientSecret(c.RegistrationAccessToken)
		if err != nil {
			return fmt.Errorf("defaultimpl: hash registration token: %w", err)
		}
		c.RegistrationAccessToken = h
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.clients[c.ID]; !exists {
		return core.ErrNoSuchClient
	}
	m.clients[c.ID] = cloneClient(c)
	return nil
}

func (m *MemoryClientStore) Delete(_ context.Context, clientID string) error {
	m.mu.Lock()
	delete(m.clients, clientID)
	m.mu.Unlock()
	return nil
}

func (m *MemoryClientStore) RotateSecret(ctx context.Context, clientID string) (string, error) {
	return m.RotateSecretWithLifecycle(ctx, clientID, 0, clientrotation.DefaultLifetime)
}

func (m *MemoryClientStore) RotateSecretWithOverlap(_ context.Context, clientID string, overlap time.Duration) (string, error) {
	return m.RotateSecretWithLifecycle(context.Background(), clientID, overlap, clientrotation.DefaultLifetime)
}

func (m *MemoryClientStore) RotateSecretWithLifecycle(_ context.Context, clientID string, overlap, lifetime time.Duration) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[clientID]
	if !ok {
		return "", core.ErrNoSuchClient
	}
	plaintext, err := generateSecret(32)
	if err != nil {
		return "", err
	}
	hashed, err := hashClientSecret(plaintext)
	if err != nil {
		return "", fmt.Errorf("defaultimpl: hash rotated secret: %w", err)
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
	return plaintext, nil
}

// ListDueForRotation implements clientrotation.ClientRotationLister: every
// active, secret-bearing client last rotated at or before olderThan. A zero
// SecretRotatedAt (never tracked) is excluded — see core.Client.SecretRotatedAt.
func (m *MemoryClientStore) ListDueForRotation(_ context.Context, olderThan time.Time) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for _, c := range m.clients {
		if c.Active && c.Secret != "" && !c.SecretRotatedAt.IsZero() && !c.SecretRotatedAt.After(olderThan) {
			out = append(out, c.ID)
		}
	}
	return out, nil
}

// ListPage implements core.PaginatedClientStore: filter (shared core
// matchers) -> sort (shared core comparators over a snapshot, so random map
// iteration cannot leak into page order) -> keyset slice. totalHint is the
// exact filtered count, so every existing TotalSize assertion holds on the
// extension path.
func (m *MemoryClientStore) ListPage(_ context.Context, q core.PageQuery) ([]*core.Client, []byte, int, error) {
	m.mu.RLock()
	clients := make([]*core.Client, 0, len(m.clients))
	for _, c := range m.clients {
		clients = append(clients, cloneClient(c))
	}
	m.mu.RUnlock()
	field, value, ok := core.ParseFilterExpr(q.Filter)
	if ok {
		if err := core.ValidateClientFilter(field, value); err != nil {
			return nil, nil, 0, err
		}
		filtered := clients[:0]
		for _, c := range clients {
			match, err := core.ClientMatches(c, field, value)
			if err != nil {
				return nil, nil, 0, err
			}
			if match {
				filtered = append(filtered, c)
			}
		}
		clients = filtered
	}
	keyID := func(c *core.Client) (string, string) { return core.ClientSortKey(c, q.OrderBy), c.ID }
	core.SortKeyset(clients, q.Desc, keyID)
	return core.KeysetSlice(clients, q, keyID)
}

// ListExpiringPage implements core.ClientExpiryLister: the windowed,
// keyset-paginated counterpart of ListExpiring's fallback full-scan path.
// Rows with a zero SecretExpiresAt (legacy/public clients) never match; the
// window sort is (SecretExpiresAt, ID) ascending — the same deterministic
// order the fallback imposes. The expiry timestamp's canonical RFC3339Nano
// form makes the sort, the cursor search, and the cursor bytes agree.
func (m *MemoryClientStore) ListExpiringPage(_ context.Context, cutoff time.Time, q core.PageQuery) ([]*core.Client, []byte, int, error) {
	m.mu.RLock()
	clients := make([]*core.Client, 0, len(m.clients))
	for _, c := range m.clients {
		clients = append(clients, cloneClient(c))
	}
	m.mu.RUnlock()
	expiring := clients[:0]
	for _, c := range clients {
		if !c.SecretExpiresAt.IsZero() && !c.SecretExpiresAt.After(cutoff) {
			expiring = append(expiring, c)
		}
	}
	keyID := func(c *core.Client) (string, string) {
		return c.SecretExpiresAt.UTC().Format(time.RFC3339Nano), c.ID
	}
	core.SortKeyset(expiring, false, keyID)
	return core.KeysetSlice(expiring, q, keyID)
}

// Compile-time interface checks.
var (
	_ core.ClientStore                            = (*MemoryClientStore)(nil)
	_ core.TenantScopedClientStore                = (*MemoryClientStore)(nil)
	_ core.ClientStoreStats                       = (*MemoryClientStore)(nil)
	_ core.PaginatedClientStore                   = (*MemoryClientStore)(nil)
	_ core.ClientExpiryLister                     = (*MemoryClientStore)(nil)
	_ clientrotation.ClientRotationLister         = (*MemoryClientStore)(nil)
	_ clientrotation.ClientSecretOverlapRotator   = (*MemoryClientStore)(nil)
	_ clientrotation.ClientSecretLifecycleRotator = (*MemoryClientStore)(nil)
)

func cloneClient(c *core.Client) *core.Client {
	if c == nil {
		return nil
	}
	cp := *c
	cp.RedirectURIs = slices.Clone(c.RedirectURIs)
	cp.RedirectURIPatterns = slices.Clone(c.RedirectURIPatterns)
	cp.AllowedScopes = slices.Clone(c.AllowedScopes)
	cp.AllowedAuthenticators = slices.Clone(c.AllowedAuthenticators)
	cp.AllowedProviderIDs = slices.Clone(c.AllowedProviderIDs)
	cp.AllowedResources = slices.Clone(c.AllowedResources)
	cp.PostLogoutRedirectURIs = slices.Clone(c.PostLogoutRedirectURIs)
	cp.AllowedAuthorizationDetailsTypes = slices.Clone(c.AllowedAuthorizationDetailsTypes)
	cp.AllowedPKCEMethods = slices.Clone(c.AllowedPKCEMethods)
	cp.AllowedRequestURIs = slices.Clone(c.AllowedRequestURIs)
	cp.JWKS = slices.Clone(c.JWKS)
	cp.GrantTypes = slices.Clone(c.GrantTypes)
	cp.Attributes = maps.Clone(c.Attributes)
	return &cp
}

// generateSecret returns a base64url-encoded random string. 32 bytes ≈ 256
// bits of entropy — comfortable for client secrets that may be long-lived.
func generateSecret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("defaultimpl: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
