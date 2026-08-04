// Package quotaprojection delivers commercial entitlement projections to a
// Snaplink SSO server through a tenant-bound machine credential.
package quotaprojection

import (
	"context"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/shared/core"
)

var (
	ErrInvalidConfig         = errors.New("quota projection: invalid configuration")
	ErrInvalidEvent          = errors.New("quota projection: invalid entitlement event")
	ErrInvalidProjection     = errors.New("quota projection: invalid projection")
	ErrInvalidReceipt        = errors.New("quota projection: invalid receipt")
	ErrProtocolConflict      = errors.New("quota projection: protocol conflict")
	ErrTokenUnavailable      = errors.New("quota projection: machine token unavailable")
	ErrAuthorizationRejected = errors.New("quota projection: authorization rejected; relay paused")
)

// Authorization is the exact trusted binding used for one tenant delivery.
// BearerToken is sensitive and must never be logged or persisted.
type Authorization struct {
	TenantID     string
	SourceSystem string
	BearerToken  string
}

// Authorizer resolves a server-registered source identity and its machine
// bearer. Implementations normally obtain a client_credentials token.
type Authorizer interface {
	Authorize(ctx context.Context, tenantID string) (Authorization, error)
}

// AuthorizerFunc adapts a function into an Authorizer.
type AuthorizerFunc func(context.Context, string) (Authorization, error)

func (f AuthorizerFunc) Authorize(ctx context.Context, tenantID string) (Authorization, error) {
	return f(ctx, tenantID)
}

// Receipt acknowledges the exact revision accepted by the SSO projection
// store. Applied is false for an idempotent or stale monotonic delivery.
type Receipt struct {
	TenantID string `json:"tenant_id"`
	Revision uint64 `json:"revision"`
	Applied  bool   `json:"applied"`
}

// Client sends one leased entitlement fact and its current projection.
type Client interface {
	Publish(
		ctx context.Context, event *commerce.OutboxEvent, projection core.TenantQuotaProjection,
	) (Receipt, error)
}

// HTTPStatusError exposes response classification only. Remote response
// bodies are intentionally excluded because they are untrusted.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("quota projection: HTTP %d", e.StatusCode)
}

func responseStatus(err error) (int, bool) {
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		return 0, false
	}
	return statusErr.StatusCode, true
}
