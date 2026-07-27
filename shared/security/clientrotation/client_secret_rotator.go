// Package clientrotation adapts core.ClientStore's existing admin-triggered
// RotateSecret into the unified credential-rotation framework
// (platform/lifecycle/rotation), so an operator can require OAuth client
// secrets to age out on a schedule instead of relying on someone remembering
// to call the admin RotateSecret RPC on a cadence of their own.
//
// A NEW leaf package rather than a file added to shared/security/securityverify
// (home of the webhook-HMAC rotator this mirrors): securityverify — and
// shared/security itself — are both already at directory_fanout_test.go's
// 10-non-test-file ceiling with no exemption, so a new file there would fail
// the gate. shared/security has room for one more SUBDIRECTORY, which keeps
// this "alongside WebhookSecretRotator" in spirit without breaching the cap.
package clientrotation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/core/corecredential"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// ClientRotationLister is an OPTIONAL core.ClientStore extension for backends
// that can enumerate clients due for scheduled secret rotation without a full
// List() + per-client filter. Mirrors protocols/oauth/oauthspi's
// RefreshTokenExpiryLister: callers type-assert before use, so adding it
// never breaks an existing ClientStore implementation, and a backend that
// doesn't implement it simply never participates in scheduled rotation — the
// existing admin-triggered RotateSecret RPC is completely unaffected either
// way.
//
// Declared here rather than beside core.ClientStore in shared/core/spi.go:
// shared/core is at directory_fanout_test.go's frozen 23-file ceiling AND
// spi.go itself is within a few lines of the 500-line maintainability budget,
// so widening core.ClientStore's own file isn't an option. This is the same
// "fold the optional extension into the consuming package" call
// RefreshTokenExpiryLister made rather than growing oauthspi's core file.
type ClientRotationLister interface {
	// ListDueForRotation returns the IDs of every ACTIVE, secret-bearing
	// client whose core.Client.SecretRotatedAt is non-zero and at or before
	// olderThan. A zero SecretRotatedAt (never tracked — see the field's
	// doc) is NEVER due: treating "unknown" as "overdue" would mass-rotate
	// every pre-existing client's secret the instant this feature is
	// enabled on an existing deployment.
	ListDueForRotation(ctx context.Context, olderThan time.Time) ([]string, error)
}

// ClientSecretRotator adapts a core.ClientStore to
// corecredential.CredentialRotator so the platform/lifecycle/rotation
// Scheduler can sweep OAuth client secrets on a cadence — the same
// admin-visible governance surface the webhook-HMAC secret already has
// (securityverify.WebhookSecretRotator) — while reusing ClientStore's
// existing RotateSecret for the actual secret generation + hashing (never
// reimplemented here).
//
// Unlike WebhookSecretRotator — ONE secret, ONE evolving version — an OAuth
// client-secret fleet is an open SET: N independent clients, each with its
// own age. corecredential.CredentialRotator's contract (Type() names ONE
// credential class; Rotate mints/returns ONE CredentialMeta) has no room for
// per-client identity, and CredentialMeta is safe to log/expose on the
// governance inventory — a client ID would defeat that safety property. So
// Rotate models ONE SWEEP: it lists every due client via
// ClientRotationLister, rotates each through the store's RotateSecret, and
// returns metadata describing the SWEEP EVENT (Version = sweep sequence
// number), never any individual secret or client identity. The governance
// inventory therefore shows "when did the fleet last get swept" — coarser
// than the webhook rotator's per-secret-version tracking, but the honest
// shape for a fleet operation plugged into a framework built for singleton
// credentials.
type ClientSecretRotator struct {
	store    core.ClientStore
	interval time.Duration
	logger   spi.Logger

	mu     sync.Mutex
	sweeps int
}

// NewClientSecretRotator binds a rotator against store using interval BOTH as
// the sweep cadence (how often rotation.Registry calls Rotate) and the
// per-client staleness bar (a client is due once its secret is >= interval
// old) — one knob, so "rotate every 90 days" means exactly that for every
// client rather than a sweep frequency independent of the staleness bar.
// logger defaults to a no-op when nil.
func NewClientSecretRotator(store core.ClientStore, interval time.Duration, logger spi.Logger) *ClientSecretRotator {
	if logger == nil {
		logger = spi.NopLogger{}
	}
	return &ClientSecretRotator{store: store, interval: interval, logger: logger}
}

var _ corecredential.CredentialRotator = (*ClientSecretRotator)(nil)

func (r *ClientSecretRotator) Type() corecredential.CredentialType {
	return corecredential.CredentialTypeOAuthClientSecret
}

// OverlapWindow deliberately returns 0 — NO overlap. A client's OLD secret
// stops validating the INSTANT RotateSecret installs the new hash: every
// shipped ClientStore backend has ONE active secret column with no
// fallback-verify-previous path. This is a documented, deliberate scope cut
// for this initial version: a real overlap window needs a previous-secret-
// hash + NotAfter fallback added to ValidateSecret in EVERY ClientStore
// backend (memory, sqlite, postgres, redis, the federation dynamic-
// registration store, and the ClientStoreCache decorator) — a much larger,
// security-sensitive cross-cutting change than an initial scheduled-rotation
// feature warrants, and one that risks under-testing a hot-path verify
// routine more than it's worth for a v1. Operators that need a grace period
// should stage their OWN rollout (rotate, then push the new secret to the
// app before the next scheduled sweep) until a future version adds real
// overlap support. KNOWN LIMITATION — tracked as follow-up work.
func (r *ClientSecretRotator) OverlapWindow() time.Duration { return 0 }

// Rotate sweeps every due client. See the type doc for why a "rotation" here
// is a sweep over many clients, not one secret.
func (r *ClientSecretRotator) Rotate(ctx context.Context) (corecredential.CredentialMeta, error) {
	lister, ok := r.store.(ClientRotationLister)
	if !ok {
		// No due-listing support: nothing to sweep. Not an error — a backend
		// without the extension simply never participates (the admin-
		// triggered RotateSecret RPC keeps working regardless). cmd's wiring
		// validates this extension is present at boot when the feature is
		// enabled, so reaching this branch in production would mean the
		// store was swapped out from under the rotator; staying graceful
		// here (rather than erroring the sweep forever) mirrors the
		// established optional-extension idiom elsewhere in this codebase.
		return r.recordSweep(0), nil
	}
	due, err := lister.ListDueForRotation(ctx, time.Now().Add(-r.interval))
	if err != nil {
		return corecredential.CredentialMeta{}, fmt.Errorf("client secret rotation: list due: %w", err)
	}
	rotated, firstErr := r.rotateDue(ctx, due)
	if firstErr != nil {
		// Fail the SWEEP so the scheduler retries soon (capped backoff). The
		// clients that DID rotate already have a fresh SecretRotatedAt and
		// drop out of the NEXT ListDueForRotation call, so a retry only
		// re-targets the stragglers — no successfully-rotated client's
		// secret is touched twice, and no failed client is left in a broken
		// state (its previous secret, which was already valid, keeps
		// serving — CredentialRotator's contract, honored per-client here).
		return corecredential.CredentialMeta{}, fmt.Errorf("client secret rotation: %d/%d client(s) rotated, first error: %w", rotated, len(due), firstErr)
	}
	return r.recordSweep(rotated), nil
}

// rotateDue rotates each due client independently: one client's failure must
// not block the rest of the fleet from rotating.
func (r *ClientSecretRotator) rotateDue(ctx context.Context, due []string) (int, error) {
	rotated := 0
	var firstErr error
	for _, id := range due {
		if _, err := r.store.RotateSecret(ctx, id); err != nil {
			r.logger.Error("scheduled client secret rotation failed for one client — its previous secret keeps serving",
				"client_id", id, "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		rotated++
	}
	return rotated, firstErr
}

// recordSweep advances the sweep counter and returns the synthetic
// governance metadata for this sweep event (see the type doc for why this is
// a sweep, not a per-client secret version). Secret material and per-client
// identity NEVER appear here — only the fleet-level fact that a sweep ran.
func (r *ClientSecretRotator) recordSweep(rotated int) corecredential.CredentialMeta {
	now := time.Now()
	r.mu.Lock()
	r.sweeps++
	version := r.sweeps
	r.mu.Unlock()
	r.logger.Info("client secret rotation sweep complete", "rotated", rotated, "sweep", version)
	return corecredential.CredentialMeta{
		ID:        fmt.Sprintf("%s/sweep-%d", corecredential.CredentialTypeOAuthClientSecret, version),
		Type:      corecredential.CredentialTypeOAuthClientSecret,
		Version:   version,
		Status:    corecredential.CredentialStatusActive,
		CreatedAt: now,
	}
}
