package spi

import (
	"context"
	"errors"
)

// ErrCodeCooldownActive is returned when a verification code for the same
// target was sent too recently. Callers should map this to HTTP 429.
var ErrCodeCooldownActive = errors.New("spi: code resend cooldown active")

// ErrCodeSendQuotaExceeded is returned internally when the target or tenant
// exhausted its fixed-window delivery budget. HTTP handlers must collapse it
// to their normal success response so the budget cannot become an account or
// target-activity oracle.
var ErrCodeSendQuotaExceeded = errors.New("spi: code send quota exceeded")

type codeSendTenantContextKey struct{}

// WithCodeSendTenant binds the resolved tenant to an out-of-band delivery.
// Stores use it only for quota partitioning; an empty tenant is the public
// partition. The target itself is never placed in context.
func WithCodeSendTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, codeSendTenantContextKey{}, tenantID)
}

// CodeSendTenant returns the tenant bound by WithCodeSendTenant.
func CodeSendTenant(ctx context.Context) string {
	tenantID, _ := ctx.Value(codeSendTenantContextKey{}).(string)
	return tenantID
}

// CodeSender is implemented by Authenticators that issue a single-use code
// out-of-band (SMS, email, push) before Authenticate is called. The Server
// exposes /auth/send-code to drive these two-step flows.
type CodeSender interface {
	SendCode(ctx context.Context, target string) error
}
