package sso

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// PARRequest is the captured authorization-request payload a client
// pushes via POST /par. The /auth/login handler later fetches it by
// request_uri and merges its fields back into the in-flight login
// request.
//
// Only the subset of /auth/login parameters that an RP needs to push
// up front is captured here — credentials are NOT, because PAR's
// whole point is to move REQUEST AUTHORITY upstream of the
// user-agent redirect, NOT to bypass user authentication.
type PARRequest struct {
	ClientID            string
	ResponseType        string
	RedirectURI         string
	Scope               []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            []string
	// AuthorizationDetails carries the RFC 9396 raw JSON array the
	// client pushed up front. Stored verbatim so extension fields
	// survive the round-trip; merged into the in-flight /auth/login
	// request just like Scope / Resource. Empty = client did not
	// push any authorization_details (legacy PAR caller).
	AuthorizationDetails json.RawMessage
	ExpiresAt            time.Time
}

// IsExpired reports whether the PAR record's lifetime has elapsed.
func (p *PARRequest) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

// PARStore persists pushed authorization requests. The request_uri
// returned by Issue MUST be single-use — Consume removes and returns
// the entry atomically so a leaked request_uri can be redeemed at
// most once. Empty / unknown / expired / already-consumed lookups
// all return ErrPARNotFound (oracle-resistance per RFC 9126 §2.2).
type PARStore interface {
	// Issue persists the request payload and returns an opaque
	// `urn:ietf:params:oauth:request_uri:<token>` string the client
	// will pass to /auth/login.
	Issue(ctx context.Context, req *PARRequest) (string, error)

	// Consume atomically removes and returns the request payload.
	// Returns ErrPARNotFound for unknown / expired / consumed URIs.
	Consume(ctx context.Context, requestURI string) (*PARRequest, error)
}

// ErrPARNotFound is the single failure mode all unknown / expired /
// consumed request_uri lookups map to. The handler maps it to
// invalid_request_uri (RFC 9126 §2.2) so attacker probing can't
// distinguish "unknown" from "consumed" / "expired".
var ErrPARNotFound = errors.New("sso: par request not found or expired")

// DefaultPARTTL is the spec-recommended request_uri lifetime. RFC
// 9126 §2.2 says SHOULD be short (60s is the common floor); we
// default to 90s to allow a slow user agent to follow the redirect.
const DefaultPARTTL = 90 * time.Second

// PARURIPrefix is the request_uri scheme defined by RFC 9126 §2.2.
// Concrete URIs look like
//
//	urn:ietf:params:oauth:request_uri:<random-token>
//
// — the prefix matches every spec-compliant request_uri and the
// suffix is whatever the PARStore minted. Single PAR endpoint per
// authorization server, so a global prefix is fine.
const PARURIPrefix = "urn:ietf:params:oauth:request_uri:"
