package spi

import (
	"context"
	"errors"
)

// ErrCodeCooldownActive is returned when a verification code for the same
// target was sent too recently. Callers should map this to HTTP 429.
var ErrCodeCooldownActive = errors.New("spi: code resend cooldown active")

// CodeSender is implemented by Authenticators that issue a single-use code
// out-of-band (SMS, email, push) before Authenticate is called. The Server
// exposes /auth/send-code to drive these two-step flows.
type CodeSender interface {
	SendCode(ctx context.Context, target string) error
}
