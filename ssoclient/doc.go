// Package ssoclient is the App-facing facade for SSO + permissions + audit.
//
// It defines three thin interfaces — AuthClient, AuthzClient, AuditClient —
// that App business code talks to. Each interface has two implementations:
//
//   - ssoclient/local — calls the snaplink/sso SDK in-process. Use it when
//     the App embeds the SDK and owns its own user / permission / audit
//     state.
//
//   - ssoclient/remote — calls a remote SSO server over gRPC (and HTTP for
//     JWKS). Use it when the App is one of many that share a central SSO
//     deployment.
//
// Each capability is selected independently: an App can have
//
//	AuthClient  = remote (central token issuance + JWKS verify)
//	AuthzClient = local  (business-specific permission rules in-process)
//	AuditClient = remote (events shipped to a central stream)
//
// or any other combination. The point is the App's business code only sees
// the interface; deployment mode is a wiring choice.
package ssoclient
