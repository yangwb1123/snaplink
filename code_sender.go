package sso

import "context"

// CodeSender is implemented by Authenticators that issue a single-use code
// out-of-band (SMS, email, push) before Authenticate is called. The Server
// exposes /auth/send-code to drive these two-step flows.
type CodeSender interface {
	SendCode(ctx context.Context, target string) error
}
