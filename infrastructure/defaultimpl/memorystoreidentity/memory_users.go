package memorystoreidentity

import (
	"context"
	"errors"
	"sync"

	"github.com/snaplink/sso/shared/core"
)

// MemoryUserProvider stores users in memory. Implements the full
// core.UserProvider including the admin extensions (List/Delete). Suitable
// for single-node and dev; databases should plug in their own implementation.
type MemoryUserProvider struct {
	mu    sync.RWMutex
	users map[string]*core.User
}

func NewMemoryUserProvider() *MemoryUserProvider {
	return &MemoryUserProvider{users: make(map[string]*core.User)}
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

func (p *MemoryUserProvider) CreateOrUpdate(_ context.Context, user *core.User) error {
	if user == nil || user.ID == "" {
		return errors.New("defaultimpl: user.ID required")
	}
	p.mu.Lock()
	p.users[user.ID] = user
	p.mu.Unlock()
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

func (p *MemoryUserProvider) Delete(_ context.Context, id string) error {
	p.mu.Lock()
	delete(p.users, id)
	p.mu.Unlock()
	return nil
}
