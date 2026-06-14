package spi

import "context"

// EmailChangeSender delivers a server-generated, single-use email-change
// verification token to the NEW address the user wants to switch to. Delivering
// to the new address (not the current one) is what proves the user controls it.
// The token is sensitive: implementations MUST NOT log or persist it.
type EmailChangeSender interface {
	SendEmailChangeToken(ctx context.Context, newEmail, token string) error
}
