package memorystoreidentity

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/snaplink/sso/shared/core"
)

// MemoryUserProvider stores users in memory. Implements the full
// core.UserProvider including the admin extensions (List/Delete) and the
// optional extension interfaces UserByUsernameProvider, UserByEmailProvider,
// UserPaginationProvider, UsernameCheckProvider, and EmailCheckProvider.
// Suitable for single-node and dev; databases should plug in their own
// implementation.
type MemoryUserProvider struct {
	mu         sync.RWMutex
	users      map[string]*core.User
	byUsername map[string]string // username → userID (lowercase key for case-insensitive matching)
	byEmail    map[string]string // email → userID (lowercase key)
}

// NewMemoryUserProvider creates a new MemoryUserProvider with empty stores.
func NewMemoryUserProvider() *MemoryUserProvider {
	return &MemoryUserProvider{
		users:      make(map[string]*core.User),
		byUsername: make(map[string]string),
		byEmail:    make(map[string]string),
	}
}

func (p *MemoryUserProvider) GetByID(_ context.Context, id string) (*core.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	u, ok := p.users[id]
	if !ok {
		return nil, core.ErrNoSuchUser
	}
	return u, nil
}

func (p *MemoryUserProvider) GetByExternalID(_ context.Context, provider, externalID string) (*core.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, u := range p.users {
		if u.Provider == provider && u.ExternalID == externalID {
			return u, nil
		}
	}
	return nil, core.ErrNoSuchUser
}

// GetByUsername implements core.UserByUsernameProvider. Exact case-insensitive
// match on username (the byUsername map is keyed on lowercase). Returns
// core.ErrNoSuchUser when not found.
func (p *MemoryUserProvider) GetByUsername(_ context.Context, username string) (*core.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	id, ok := p.byUsername[strings.ToLower(username)]
	if !ok {
		return nil, core.ErrNoSuchUser
	}
	u, ok := p.users[id]
	if !ok {
		// Stale index entry — the user was deleted without updating byUsername.
		// This should not happen in normal operation; rebuild the index.
		delete(p.byUsername, strings.ToLower(username))
		return nil, core.ErrNoSuchUser
	}
	return u, nil
}

// GetByEmail implements core.UserByEmailProvider. Case-insensitive match on
// email. Returns core.ErrNoSuchUser when not found.
func (p *MemoryUserProvider) GetByEmail(_ context.Context, email string) (*core.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	id, ok := p.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, core.ErrNoSuchUser
	}
	u, ok := p.users[id]
	if !ok {
		delete(p.byEmail, strings.ToLower(email))
		return nil, core.ErrNoSuchUser
	}
	return u, nil
}

// UsernameExists implements core.UsernameCheckProvider.
func (p *MemoryUserProvider) UsernameExists(_ context.Context, username string) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.byUsername[strings.ToLower(username)]
	return ok, nil
}

// EmailExists implements core.EmailCheckProvider.
func (p *MemoryUserProvider) EmailExists(_ context.Context, email string) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.byEmail[strings.ToLower(email)]
	return ok, nil
}

func (p *MemoryUserProvider) CreateOrUpdate(_ context.Context, user *core.User) error {
	if user == nil || user.ID == "" {
		return errors.New("defaultimpl: user.ID required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	// Validate uniqueness BEFORE mutating either index: a rejected update
	// must leave the existing user's current username/email index entries
	// intact, not half-deleted. (Deleting the old keys first and returning
	// ErrUserExists partway through would strand the existing user
	// unfindable by GetByUsername/GetByEmail until a later call succeeds.)
	if user.Username != "" {
		key := strings.ToLower(user.Username)
		if ownerID, taken := p.byUsername[key]; taken && ownerID != user.ID {
			return core.ErrUserExists
		}
	}
	if user.Email != "" {
		key := strings.ToLower(user.Email)
		if ownerID, taken := p.byEmail[key]; taken && ownerID != user.ID {
			return core.ErrUserExists
		}
	}

	// Both checks passed: now safe to replace this user's index entries.
	if existing, ok := p.users[user.ID]; ok {
		if existing.Username != "" {
			delete(p.byUsername, strings.ToLower(existing.Username))
		}
		if existing.Email != "" {
			delete(p.byEmail, strings.ToLower(existing.Email))
		}
	}
	if user.Username != "" {
		p.byUsername[strings.ToLower(user.Username)] = user.ID
	}
	if user.Email != "" {
		p.byEmail[strings.ToLower(user.Email)] = user.ID
	}

	p.users[user.ID] = user
	return nil
}

func (p *MemoryUserProvider) List(_ context.Context) ([]*core.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*core.User, 0, len(p.users))
	for _, u := range p.users {
		out = append(out, u)
	}
	return out, nil
}

// ListPaginated implements core.UserPaginationProvider. Returns users sorted
// by ID for deterministic pagination. Clamps limit to 100.
func (p *MemoryUserProvider) ListPaginated(_ context.Context, offset, limit int) ([]*core.User, int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	total := len(p.users)
	if offset > total {
		offset = total
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	// Sort by ID for deterministic ordering.
	sorted := make([]string, 0, total)
	for id := range p.users {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)

	// Apply offset + limit.
	end := offset + limit
	if end > total {
		end = total
	}
	sorted = sorted[offset:end]

	out := make([]*core.User, 0, len(sorted))
	for _, id := range sorted {
		out = append(out, p.users[id])
	}
	return out, total, nil
}

func (p *MemoryUserProvider) Delete(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if u, ok := p.users[id]; ok {
		if u.Username != "" {
			delete(p.byUsername, strings.ToLower(u.Username))
		}
		if u.Email != "" {
			delete(p.byEmail, strings.ToLower(u.Email))
		}
		delete(p.users, id)
	}
	return nil
}
