package defaultimpl

import (
	"context"
	"fmt"
	"sync"

	"github.com/snaplink/sso"
)

// MemoryClientStore stores client applications in memory.
type MemoryClientStore struct {
	clients sync.Map // clientID -> *sso.Client
}

func NewMemoryClientStore() *MemoryClientStore {
	return &MemoryClientStore{}
}

func (m *MemoryClientStore) Add(client *sso.Client) {
	m.clients.Store(client.ID, client)
}

func (m *MemoryClientStore) Get(ctx context.Context, clientID string) (*sso.Client, error) {
	v, ok := m.clients.Load(clientID)
	if !ok {
		return nil, fmt.Errorf("client not found")
	}
	return v.(*sso.Client), nil
}

func (m *MemoryClientStore) ValidateSecret(ctx context.Context, clientID, clientSecret string) error {
	v, ok := m.clients.Load(clientID)
	if !ok {
		return fmt.Errorf("client not found")
	}
	c := v.(*sso.Client)
	if c.Secret != clientSecret {
		return fmt.Errorf("invalid client secret")
	}
	if !c.Active {
		return fmt.Errorf("client is inactive")
	}
	return nil
}
