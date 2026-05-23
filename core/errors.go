package core

import "errors"

// Sentinel errors returned by storage interfaces (ClientStore, UserProvider,
// SessionManager, TokenIssuer). Admin RPCs translate these into the
// appropriate gRPC status codes (NotFound, AlreadyExists, Unimplemented),
// which the gRPC-Gateway then maps to HTTP 404 / 409 / 501.
var (
	ErrClientExists = errors.New("sso: client already exists")
	ErrNoSuchClient = errors.New("sso: client not found")

	ErrUserExists = errors.New("sso: user already exists")
	ErrNoSuchUser = errors.New("sso: user not found")

	ErrSessionNotFound = errors.New("sso: session not found")

	// ErrUnsupportedOperation is returned by token issuers (and any other
	// store) for capabilities the backend cannot honor — e.g. JWT issuers
	// have no notion of "list active tokens" because tokens are stateless.
	// Admin RPCs translate this to gRPC Unimplemented / HTTP 501.
	ErrUnsupportedOperation = errors.New("sso: operation not supported by backend")
)
