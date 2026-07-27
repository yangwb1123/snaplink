package securityverify

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core/corecredential"
)

// WebhookSecretBytes is the size of a generated webhook HMAC secret.
// 32 bytes matches the HMAC-SHA256 block-independent key strength ceiling —
// longer keys are hashed down by HMAC and add nothing.
const WebhookSecretBytes = 32

// RotatingWebhookSecret holds the CURRENT outbound webhook HMAC signing
// secret plus, during an overlap window after a rotation, the demoted
// previous one. Outbound deliveries always sign with the current secret;
// receiver-side Verify accepts BOTH until the window closes, so in-flight
// retries/redeliveries signed pre-rotation still authenticate. Safe for
// concurrent use.
type RotatingWebhookSecret struct {
	mu        sync.RWMutex
	current   []byte
	version   int
	createdAt time.Time

	// previous is the demoted secret, accepted (verify-only) until
	// prevNotAfter. Nil outside an overlap window.
	previous     []byte
	prevNotAfter time.Time
}

// NewRotatingWebhookSecret seeds the holder at version 1. An empty initial
// generates a fresh random secret (crypto/rand failure is the only error).
// Operators migrating from a static configured secret pass it here so
// receivers keep validating uninterrupted until the first rotation.
func NewRotatingWebhookSecret(initial []byte) (*RotatingWebhookSecret, error) {
	if len(initial) == 0 {
		var err error
		if initial, err = generateWebhookSecret(); err != nil {
			return nil, err
		}
	}
	return &RotatingWebhookSecret{
		current:   append([]byte(nil), initial...),
		version:   1,
		createdAt: time.Now(),
	}, nil
}

func generateWebhookSecret() ([]byte, error) {
	b := make([]byte, WebhookSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("webhook secret: generate: %w", err)
	}
	return b, nil
}

// Current returns a copy of the signing secret for outbound deliveries.
// Shape-compatible with WebhookSink's secret source seam.
func (r *RotatingWebhookSecret) Current() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]byte(nil), r.current...)
}

// Meta returns the governance metadata of the CURRENT version. ID is a
// synthetic version handle — never derived from the secret bytes.
func (r *RotatingWebhookSecret) Meta() corecredential.CredentialMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return webhookSecretMeta(r.version, r.createdAt)
}

func webhookSecretMeta(version int, createdAt time.Time) corecredential.CredentialMeta {
	return corecredential.CredentialMeta{
		ID:        fmt.Sprintf("%s/v%d", corecredential.CredentialTypeWebhookHMAC, version),
		Type:      corecredential.CredentialTypeWebhookHMAC,
		Version:   version,
		Status:    corecredential.CredentialStatusActive,
		CreatedAt: createdAt,
		Algorithm: "HMAC-SHA256",
	}
}

// Rotate mints a fresh secret and demotes the current one into the overlap
// window (accepted until now+overlap; overlap <= 0 drops it immediately).
// On generation failure the state is untouched — the old secret keeps
// serving, per the CredentialRotator contract.
func (r *RotatingWebhookSecret) Rotate(now time.Time, overlap time.Duration) (corecredential.CredentialMeta, error) {
	next, err := generateWebhookSecret()
	if err != nil {
		return corecredential.CredentialMeta{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if overlap > 0 {
		r.previous = r.current
		r.prevNotAfter = now.Add(overlap)
	} else {
		r.previous = nil
		r.prevNotAfter = time.Time{}
	}
	r.current = next
	r.version++
	r.createdAt = now
	return webhookSecretMeta(r.version, now), nil
}

// Verify is the receiver-side check across the rotation window: the header
// is accepted when it validates against the current secret OR, before the
// overlap deadline, against the demoted previous one. Each attempt uses the
// constant-time single-secret verifier; the current secret's error is
// returned when both fail so a rejected caller learns nothing about the
// overlap state.
func (r *RotatingWebhookSecret) Verify(header string, body []byte, now time.Time, tolerance time.Duration) error {
	r.mu.RLock()
	current := r.current
	previous := r.previous
	prevNotAfter := r.prevNotAfter
	r.mu.RUnlock()

	if len(current) == 0 {
		return corecredential.ErrNoActiveCredential
	}
	err := VerifyWebhookSignature(current, header, body, now, tolerance)
	if err == nil {
		return nil
	}
	if len(previous) > 0 && now.Before(prevNotAfter) {
		if VerifyWebhookSignature(previous, header, body, now, tolerance) == nil {
			return nil
		}
	}
	return err
}

// WebhookSecretRotator adapts a RotatingWebhookSecret to the rotation
// framework (corecredential.CredentialRotator): each Rotate mints + installs
// a new secret with this rotator's overlap window.
type WebhookSecretRotator struct {
	secret  *RotatingWebhookSecret
	overlap time.Duration
}

// NewWebhookSecretRotator binds a rotator to secret with the given overlap
// window. The window must cover the receiver's redelivery/retry horizon plus
// the receiver-side timestamp tolerance, or pre-rotation in-flight
// deliveries fail verification.
func NewWebhookSecretRotator(secret *RotatingWebhookSecret, overlap time.Duration) *WebhookSecretRotator {
	return &WebhookSecretRotator{secret: secret, overlap: overlap}
}

var (
	_ corecredential.CredentialRotator  = (*WebhookSecretRotator)(nil)
	_ corecredential.DependencyReporter = (*WebhookSecretRotator)(nil)
)

func (w *WebhookSecretRotator) Type() corecredential.CredentialType {
	return corecredential.CredentialTypeWebhookHMAC
}

// Dependents reports that rotating the webhook HMAC secret affects outbound
// webhook receivers — they must adopt the new verification secret (both are
// accepted during the overlap window) before the old one is retired.
func (w *WebhookSecretRotator) Dependents() []corecredential.Dependency {
	return []corecredential.Dependency{corecredential.DependencyWebhookReceivers}
}

func (w *WebhookSecretRotator) OverlapWindow() time.Duration { return w.overlap }

func (w *WebhookSecretRotator) Rotate(_ context.Context) (corecredential.CredentialMeta, error) {
	return w.secret.Rotate(time.Now(), w.overlap)
}

// CurrentMeta reports the currently-installed version so the rotation
// inventory shows it before the scheduler's first rotation fires.
func (w *WebhookSecretRotator) CurrentMeta() corecredential.CredentialMeta {
	return w.secret.Meta()
}
