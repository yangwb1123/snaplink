// Package bcl provides reliable delivery and dead-letter governance for
// OpenID Connect Back-Channel Logout notifications.
package bcl

import (
	"context"
	"errors"
	"time"
)

const (
	DefaultRetryInterval = 30 * time.Second
	DefaultBatchSize     = 50
	DefaultLeaseDuration = 30 * time.Second
	DefaultTimeout       = 5 * time.Second
	DefaultMaxAttempts   = 3
	DefaultRetryBase     = 50 * time.Millisecond
)

var (
	ErrNotFound         = errors.New("bcl: failure not found")
	ErrLeaseUnavailable = errors.New("bcl: failure is already being replayed")
	ErrReplayCleanup    = errors.New("bcl: delivery succeeded but queue cleanup failed")
)

type Request struct {
	Subject  string
	Audience string
	TTL      time.Duration
	SID      string
}

type Issuer interface {
	IssueLogoutToken(ctx context.Context, req *Request) (string, error)
}

type Notifier interface {
	Notify(ctx context.Context, uri string, logoutToken string) error
}

// Failure contains only the business inputs needed to mint a fresh logout
// token. Signed logout tokens are deliberately never persisted.
type Failure struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id,omitempty"`
	ClientID      string    `json:"client_id"`
	Subject       string    `json:"subject"`
	TokenSubject  string    `json:"token_subject"`
	URI           string    `json:"uri"`
	SID           string    `json:"sid,omitempty"`
	Attempts      int       `json:"attempts"`
	LastError     string    `json:"last_error"`
	Permanent     bool      `json:"permanent"`
	FirstFailedAt time.Time `json:"first_failed_at"`
	LastFailedAt  time.Time `json:"last_failed_at"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	DeliveredAt   time.Time `json:"delivered_at,omitzero"`
}

type Filter struct {
	TenantID  string
	Limit     int
	DueBefore time.Time
}

// Store uses a lease token for replay ownership. Ack and Reschedule must reject
// stale tokens so a slow worker cannot overwrite a newer worker's result.
type Store interface {
	Enqueue(ctx context.Context, failure Failure) (Failure, error)
	List(ctx context.Context, filter Filter) ([]Failure, error)
	Claim(ctx context.Context, id, tenantID string, lease time.Duration) (Failure, string, error)
	Ack(ctx context.Context, failure Failure, leaseToken string) error
	Reschedule(ctx context.Context, failure Failure, leaseToken string) error
}

type FailureRecorder interface {
	RecordFailure(ctx context.Context, failure Failure) error
}

type AdminManager interface {
	FailureRecorder
	ListFailures(ctx context.Context, tenantID string, limit int) ([]Failure, error)
	ReplayFailure(ctx context.Context, id, tenantID string) (Failure, error)
	ReplayDue(ctx context.Context, tenantID string, limit int) (ReplaySummary, error)
}

type ReplaySummary struct {
	Attempted int `json:"attempted"`
	Delivered int `json:"delivered"`
	Failed    int `json:"failed"`
	Busy      int `json:"busy"`
}
