package spi

import "context"

// InvitationSender delivers a server-generated, single-use org-invitation token
// to the invited email address (typically as a link the recipient clicks to
// accept). The token is a live credential: implementations MUST NOT log or
// persist it. tenantID + role are passed so the message can name the org and the
// standing being offered.
type InvitationSender interface {
	SendInvitation(ctx context.Context, email, tenantID, role, token string) error
}
