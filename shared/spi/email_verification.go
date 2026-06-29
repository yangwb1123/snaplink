package spi

import "context"

// EmailVerificationSender delivers a server-generated, single-use email
// verification token to the target address during self-service signup.
// The token is sensitive: implementations MUST NOT log or persist it.
type EmailVerificationSender interface {
	SendEmailVerificationToken(ctx context.Context, email, token string) error
}
