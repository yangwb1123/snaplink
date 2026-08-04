// Package auditgovernance relays tenant commerce facts to the separately
// deployed Snaplink Audit Governance service.
package auditgovernance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

var (
	ErrInvalidConfig         = errors.New("audit governance: invalid configuration")
	ErrInvalidEvent          = errors.New("audit governance: invalid commerce event")
	ErrInvalidReceipt        = errors.New("audit governance: invalid receipt")
	ErrProtocolConflict      = errors.New("audit governance: protocol conflict")
	ErrTokenUnavailable      = errors.New("audit governance: client credentials token unavailable")
	ErrAuthorizationRejected = errors.New("audit governance: authorization rejected; relay paused")
)

// SourceBinding is the trusted identity a client_credentials implementation
// must bind into the access token. Neither value is taken from an HTTP body.
type SourceBinding struct {
	TenantID     string
	SourceSystem string
}

// ClientCredentialsTokenSource supplies tenant-and-source-bound service
// tokens. Implementations own caching and refresh; callers must never log the
// returned bearer value.
type ClientCredentialsTokenSource interface {
	AccessToken(ctx context.Context, binding SourceBinding) (string, error)
}

// Receipt is the narrow acknowledgement needed to complete an outbox fact.
type Receipt struct {
	EventID    string
	TenantID   string
	Status     string
	AcceptedAt time.Time
	Duplicate  bool
}

// Client publishes one leased commerce outbox fact. A nil error means the
// remote service returned 202 with a matching ledgered-or-later receipt.
type Client interface {
	Publish(ctx context.Context, event *commerce.OutboxEvent) (Receipt, error)
}

// HTTPStatusError exposes only response classification data. Response bodies
// are intentionally excluded because they may contain credentials or PII.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("audit governance: HTTP %d", e.StatusCode)
}

func responseStatus(err error) (int, bool) {
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		return 0, false
	}
	return statusErr.StatusCode, true
}
