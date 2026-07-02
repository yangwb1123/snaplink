package caep

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"
)

// Delivery-retry defaults. Retry is OPT-IN (default attempts = 1, i.e.
// today's single-shot behavior): the shipped receiver answers 500 on a
// transient post-validation failure precisely so a transmitter MAY retry
// (receiver_receive.go), but each retry holds a broadcast goroutine
// through its backoff + POST, so the operator sizes the budget.
const (
	DefaultDeliveryRetryInitialBackoff = 500 * time.Millisecond
	DefaultDeliveryRetryMaxBackoff     = 5 * time.Second
)

// WithDeliveryRetry caps TOTAL delivery attempts per SET per receiver,
// including the first (3 = try once, retry twice). Values <= 1 keep the
// single-shot default.
func WithDeliveryRetry(maxAttempts int) Option {
	return func(t *Transmitter) {
		if maxAttempts > 1 {
			t.retryMaxAttempts = maxAttempts
		}
	}
}

// WithDeliveryRetryBackoff tunes the exponential inter-attempt backoff
// (doubling from initial, +-25% jitter, capped at max — the same shape as
// auditsink.RetryingSink). Non-positive values keep the defaults.
func WithDeliveryRetryBackoff(initial, max time.Duration) Option {
	return func(t *Transmitter) {
		if initial > 0 {
			t.retryInitialBackoff = initial
		}
		if max > 0 {
			t.retryMaxBackoff = max
		}
	}
}

// receiverStatusError carries the receiver's non-2xx status so the retry
// loop can classify. The Error() text stays byte-identical to the
// pre-retry fmt.Errorf so caep_broadcast_failed audit Reasons don't change.
type receiverStatusError struct{ status int }

func (e *receiverStatusError) Error() string { return fmt.Sprintf("non-2xx status %d", e.status) }

// mintError marks a local signing failure — permanent for retry purposes
// (the signer is local; looping won't fix a bad key). Keeps the existing
// "mint: " audit-reason prefix.
type mintError struct{ err error }

func (e *mintError) Error() string { return "mint: " + e.err.Error() }

// retryableDeliveryError: 5xx and 429 are the receiver's transient
// signals (our own receiver 500s on a post-validation store outage BY
// CONTRACT so the transmitter retries); other 4xx means the SET was
// REJECTED — retrying re-sends the same rejection. Transport errors
// (dial/TLS/timeout) are retryable.
func retryableDeliveryError(err error) bool {
	var se *receiverStatusError
	if errors.As(err, &se) {
		return se.status >= http.StatusInternalServerError || se.status == http.StatusTooManyRequests
	}
	var me *mintError
	return !errors.As(err, &me)
}

// attemptDelivery mints a FRESH SET and POSTs it under the per-attempt
// timeout. Fresh mint per attempt is REQUIRED, not a nicety: the
// receiver's jti-replay guard (MarkSeen, validation step 7) fires BEFORE
// the revoke action, so a byte-identical retransmit of a SET that 500ed
// would be rejected as a replay. A new jti + iat per attempt is safe —
// the events payload is identical and idempotent on the receiver.
func (t *Transmitter) attemptDelivery(endpoint, auth string, req buildSETRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()
	set, err := mintSET(ctx, t.signer, req, t.setTTL)
	if err != nil {
		return &mintError{err}
	}
	return t.post(ctx, endpoint, auth, set)
}

// waitBackoff sleeps before retry N (0-indexed): initial<<N, +-25%
// jitter, capped at retryMaxBackoff (auditsink.RetryingSink.backoff
// shape). Returns false when Close has fired — shutdown aborts pending
// backoffs so draining is bounded by the in-flight POST, never by the
// remaining retry chain.
func (t *Transmitter) waitBackoff(attempt int) bool {
	base := t.retryInitialBackoff << attempt
	if base <= 0 || base > t.retryMaxBackoff {
		base = t.retryMaxBackoff
	}
	timer := time.NewTimer(time.Duration(float64(base) * (0.75 + rand.Float64()*0.5)))
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-t.stop:
		return false
	}
}
