package defaultimpl

import (
	"context"
	"errors"
	"sync"

	"github.com/snaplink/sso/interfaces/sso"
)

// MemoryUserProvider stores users in memory. Implements the full
// sso.UserProvider including the admin extensions (List/Delete). Suitable
// for single-node and dev; databases should plug in their own implementation.
type MemoryUserProvider struct {
	mu    sync.RWMutex
	users map[string]*sso.User
}

func NewMemoryUserProvider() *MemoryUserProvider {
	return &MemoryUserProvider{users: make(map[string]*sso.User)}
}

func (p *MemoryUserProvider) GetByID(_ context.Context, id string) (*sso.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	u, ok := p.users[id]
	if !ok {
		return nil, sso.ErrNoSuchUser
	}
	return u, nil
}

func (p *MemoryUserProvider) GetByExternalID(_ context.Context, provider, externalID string) (*sso.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, u := range p.users {
		if u.Provider == provider && u.ExternalID == externalID {
			return u, nil
		}
	}
	return nil, sso.ErrNoSuchUser
}

func (p *MemoryUserProvider) CreateOrUpdate(_ context.Context, user *sso.User) error {
	if user == nil || user.ID == "" {
		return errors.New("defaultimpl: user.ID required")
	}
	p.mu.Lock()
	p.users[user.ID] = user
	p.mu.Unlock()
	return nil
}

func (p *MemoryUserProvider) List(_ context.Context) ([]*sso.User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*sso.User, 0, len(p.users))
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
