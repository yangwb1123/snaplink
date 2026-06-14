package spi

import "context"

// PasswordResetResolver maps a submitted login identifier (username, email, or
// phone — whatever the deployment logs in with) to the stable userID the
// PasswordCredentialStore is keyed by. It is the operator-implemented,
// deployment-specific seam for the forgot-password flow — the same mapping the
// login authenticator already performs (its signature matches
// authenticators.UserIDResolver, so an existing resolver can be reused via a
// conversion). It lives here, not in authenticators, because the server package
// imports spi but not authenticators (which would be an import cycle).
//
// Return ("", nil) or an error for an unknown identifier — the handler treats
// both the same and never reveals which (anti-enumeration).
type PasswordResetResolver func(ctx context.Context, identifier string) (userID string, err error)

// PasswordResetDeliveryResolver maps a resolved userID to the out-of-band
// delivery target (email address, phone number) the reset token is sent to.
// Kept separate from PasswordResetResolver so identifier->userID and
// userID->address stay distinct concerns. Return ("", nil) or an error when
// the user has no deliverable address — the handler still returns 200.
type PasswordResetDeliveryResolver func(ctx context.Context, userID string) (deliveryTarget string, err error)

// PasswordResetSender delivers a server-generated, single-use reset token to a
// delivery target out-of-band (email link, SMS code, push). Unlike CodeSender
// (which generates its OWN code), this conveys a token the server minted. The
// token is credential-takeover material: implementations MUST NOT log or
// persist it, and SHOULD deliver it over a confidential channel.
type PasswordResetSender interface {
	SendResetToken(ctx context.Context, deliveryTarget, token string) error
}
