package generate

// authenticatorTemplate generates a new authenticator implementation.
// Authenticators implement core.Authenticator and handle user authentication
// via various mechanisms (password, OIDC, SAML, LDAP, etc.).
const authenticatorTemplate = `package {{.Package}}

import (
	"context"
	"fmt"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// {{.Name}}Authenticator authenticates users using {{.Description}}.
// Implements core.Authenticator.
type {{.Name}}Authenticator struct {
	// config holds the authenticator configuration.
	config {{.Name}}Config
	// logger for debugging and audit trails.
	logger spi.Logger
}

// {{.Name}}Config holds configuration for the {{.Name}} authenticator.
type {{.Name}}Config struct {
	// TODO: Add authenticator-specific configuration fields.
	// Example:
	// Endpoint string
	// ClientID string
	// Timeout  time.Duration
}

// New{{.Name}}Authenticator creates a new {{.Name}} authenticator.
func New{{.Name}}Authenticator(config {{.Name}}Config, logger spi.Logger) *{{.Name}}Authenticator {
	return &{{.Name}}Authenticator{
		config: config,
		logger: logger,
	}
}

// Name returns the unique identifier for this authenticator.
func (a *{{.Name}}Authenticator) Name() string {
	return "{{.LowerName}}"
}

// Authenticate validates credentials and returns the authenticated user info.
// This is called during the initial authentication attempt.
func (a *{{.Name}}Authenticator) Authenticate(ctx context.Context, req *core.AuthRequest) (*sso.AuthResult, error) {
	if req == nil {
		return nil, fmt.Errorf("auth request is nil")
	}

	// TODO: Replace with your {{.Description}} authentication logic.
	// Example pattern:
	// 1. Extract credentials from req.Credentials map
	// 2. Validate against your authentication backend
	// 3. Return AuthResult with user info on success
	// 4. Return error on failure (triggers next authenticator in chain)
	//
	// After filling in your logic, remove this marker.

	// username := req.Credentials["username"]
	// password := req.Credentials["password"]
	// 
	// user, err := a.verify(ctx, username, password)
	// if err != nil {
	// 	return nil, fmt.Errorf("{{.LowerName}} auth failed: %w", err)
	// }

	return nil, core.ErrNoSuchUser
}

// Callback handles the return from an external identity provider.
// For redirect-based flows (OIDC, SAML), this processes the callback.
// For direct credential auth (password), this can return nil, nil.
func (a *{{.Name}}Authenticator) Callback(ctx context.Context, state *core.CallbackState) (*sso.AuthResult, error) {
	if state == nil {
		return nil, fmt.Errorf("callback state is nil")
	}

	// TODO: Replace with your {{.Description}} callback logic if applicable.
	// For OIDC/SAML: exchange code/assertion for user info.
	// For direct auth: return nil, nil (no callback needed).
	//
	// After filling in your logic, remove this marker.

	return nil, core.ErrNoSuchUser
}

// LoginURL returns the URL to redirect the user to for login.
// For direct credential auth (password), return empty string.
// For redirect-based flows, return the IdP login URL.
func (a *{{.Name}}Authenticator) LoginURL(state string) string {
	// TODO: Implement if this is a redirect-based authenticator.
	// Example:
	// return fmt.Sprintf("https://idp.example.com/auth?state=%s&client_id=%s", 
	// 	url.QueryEscape(state), url.QueryEscape(a.config.ClientID))
	return ""
}

// LockoutIdentity returns the canonical identity for brute-force lockout.
// Implements optional core.LockoutKeyer interface.
// Return empty string if this authenticator is lockout-unkeyable.
func (a *{{.Name}}Authenticator) LockoutIdentity(credential map[string]string) string {
	// TODO: Return the primary identity field for lockout keying.
	// Example:
	// return credential["username"] // or "email", "phone", etc.
	return credential["username"]
}
`

// storeTemplate generates a new storage backend implementation.
// Stores implement storage interfaces from shared/core/spi.go for persisting
// users, clients, tokens, sessions, etc. The generated store ships a WORKING
// in-memory map (compiles + behaves correctly out of the box) rather than
// stub methods that return "not implemented" errors — swap the map for a
// real backend (SQL, Redis, etc.) and adapt the method set to whichever core
// storage interface you're implementing (see the TODO block at the bottom).
const storeTemplate = `package {{.Package}}

import (
	"context"
	"fmt"
	"sync"
)

// {{.Name}}Store implements {{.Description}} storage.
// Ships with a working in-memory map as a starting point. Replace the map
// with your real backend (database, cache, external service, etc.) and
// adapt the method set below to whichever core storage interface you're
// implementing — see the reference list at the bottom of this file.
type {{.Name}}Store struct {
	// mu protects concurrent access to the store.
	// Remove if your backend handles concurrency internally.
	mu sync.RWMutex

	// entries is the working default backing store. Replace with your real
	// backend fields (e.g. db *sql.DB, client *redis.Client) and change the
	// value type from any to your concrete domain type (*core.User,
	// *core.Client, etc.) once you know which core interface this implements.
	entries map[string]any
}

// New{{.Name}}Store creates a new {{.Name}} store.
func New{{.Name}}Store() (*{{.Name}}Store, error) {
	// TODO: Initialize your real storage backend connection instead of the
	// in-memory map below.
	// Example:
	// db, err := sql.Open("postgres", dsn)
	// if err != nil {
	// 	return nil, fmt.Errorf("connect to database: %w", err)
	// }
	// if err := db.Ping(); err != nil {
	// 	return nil, fmt.Errorf("ping database: %w", err)
	// }

	return &{{.Name}}Store{entries: make(map[string]any)}, nil
}

// Close releases resources held by the store.
// Implement io.Closer if your backend requires cleanup.
func (s *{{.Name}}Store) Close() error {
	// TODO: Close backend connections.
	// Example:
	// return s.db.Close()
	return nil
}

// Get retrieves an entity by ID. Replace the any return type with your
// concrete domain type (*core.User, *core.Client, ...) once you know which
// core storage interface this implements.
func (s *{{.Name}}Store) Get(_ context.Context, id string) (any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// TODO: Replace with your backend query logic once this is more than an
	// in-memory map. Example (SQL):
	// var entity core.Entity
	// err := s.db.QueryRowContext(ctx,
	// 	"SELECT id, name, created_at FROM entities WHERE id = $1", id).
	// 	Scan(&entity.ID, &entity.Name, &entity.CreatedAt)
	// if err == sql.ErrNoRows {
	// 	return nil, core.ErrNoSuchUser // or the ErrNoSuch* sentinel you implement
	// }

	v, ok := s.entries[id]
	if !ok {
		return nil, fmt.Errorf("{{.LowerName}} store: %q not found", id)
	}
	return v, nil
}

// Create stores a new entity under id.
func (s *{{.Name}}Store) Create(_ context.Context, id string, entity any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// TODO: Replace with your backend insert logic. Example (SQL):
	// _, err := s.db.ExecContext(ctx,
	// 	"INSERT INTO entities (id, name, created_at) VALUES ($1, $2, $3)",
	// 	entity.ID, entity.Name, entity.CreatedAt)

	if _, exists := s.entries[id]; exists {
		return fmt.Errorf("{{.LowerName}} store: %q already exists", id)
	}
	s.entries[id] = entity
	return nil
}

// Update replaces an existing entity. Returns an error if id is unknown —
// callers that want upsert semantics should check first or add their own
// CreateOrUpdate wrapper.
func (s *{{.Name}}Store) Update(_ context.Context, id string, entity any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[id]; !exists {
		return fmt.Errorf("{{.LowerName}} store: %q not found", id)
	}
	s.entries[id] = entity
	return nil
}

// Delete removes an entity by ID. Deleting a missing ID is a no-op success
// (idempotent), matching the convention most core storage interfaces use.
func (s *{{.Name}}Store) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// TODO: Replace with your backend delete logic. Example (SQL):
	// result, err := s.db.ExecContext(ctx, "DELETE FROM entities WHERE id = $1", id)

	delete(s.entries, id)
	return nil
}

// List returns every stored entity. Replace with a paginated/filtered query
// once this is backed by a real database — an unbounded List is fine for a
// scaffold default, not for production scale.
func (s *{{.Name}}Store) List(_ context.Context) ([]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]any, 0, len(s.entries))
	for _, v := range s.entries {
		out = append(out, v)
	}
	return out, nil
}

// TODO: Adapt the method set above to whichever core storage interface you're
// implementing (rename methods, change the any value type to a concrete
// domain type). Reference shapes:
//
// For UserProvider (core.UserProvider): GetByID/GetByExternalID/
//   CreateOrUpdate/List/Delete returning *core.User — see
//   infrastructure/defaultimpl/memorystoreidentity for a real reference.
//
// For ClientStore (core.ClientStore): Get/Add/Update/Delete/List returning
//   *core.Client — see
//   infrastructure/defaultimpl/memorystoreidentity/memory_clients.go.
//
// For SessionManager (core.SessionManager): Create/Get/Delete/ListByUser/
//   RevokeByUser returning *core.Session.
//
// For TokenIssuer (core.TokenIssuer): Issue/Validate/Revoke — see
//   infrastructure/defaultimpl's Ed25519/ECDSA/RSA issuers for a real
//   reference implementation.
`
