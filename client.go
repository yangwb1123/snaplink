package sso

import "context"

// ClientStore manages registered SSO client applications. Get + ValidateSecret
// are the runtime hot path; the rest (List/Update/Delete/RotateSecret/Add)
// power the admin control plane and are also used at boot to load YAML seed
// clients. Backends backed by a database can implement these directly;
// in-memory or YAML-only setups can wrap defaultimpl.MemoryClientStore.
type ClientStore interface {
	Get(ctx context.Context, clientID string) (*Client, error)
	ValidateSecret(ctx context.Context, clientID, clientSecret string) error

	// List returns every registered client. Order is unspecified.
	List(ctx context.Context) ([]*Client, error)

	// Add inserts a new client. Returns ErrClientExists if the ID is taken —
	// admin Create RPCs map this to AlreadyExists/409.
	Add(ctx context.Context, c *Client) error

	// Update replaces an existing client by ID. ErrNoSuchClient when missing.
	Update(ctx context.Context, c *Client) error

	// Delete removes a client by ID. Idempotent — missing IDs return nil so
	// reconciliation loops don't churn.
	Delete(ctx context.Context, clientID string) error

	// RotateSecret generates a new secret for the client, persists it, and
	// returns the new value. Implementations choose secret format/length;
	// callers MUST treat the returned string as opaque.
	RotateSecret(ctx context.Context, clientID string) (string, error)
}
