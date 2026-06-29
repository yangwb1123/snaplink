package oauthspi

import (
	"context"
	"errors"
	"time"
)

// GrantCIBA is the grant_type the client polls with on /token to
// redeem an approved CIBA (Client-Initiated Backchannel Authentication)
// request. OpenID Connect CIBA Core 1.0 §10.1 defines this URN for the
// poll + ping delivery modes; we implement poll only.
const GrantCIBA = "urn:openid:params:grant-type:ciba"

// AuthReqIDPrefix is the opaque-id namespace minted by Issue. Kept
// distinct from the device_code / request_uri spaces so a leaked id
// can't be cross-redeemed against a different endpoint.
const AuthReqIDPrefix = "ciba_"

// DefaultCIBARequestTTL is the OIDC CIBA Core recommended lifetime of a
// backchannel auth request. The user has this long to confirm out of
// band before the auth_req_id expires (poll → expired_token).
const DefaultCIBARequestTTL = 120 * time.Second

// DefaultCIBAPollInterval is the minimum seconds a poll-mode client
// MUST wait between /token polls (CIBA Core §10.2 `interval`). Reused
// for the slow_down anti-thrash rule, mirroring the device-flow grant.
const DefaultCIBAPollInterval = 5 * time.Second

// CIBAStatus is the lifecycle of one backchannel auth request. The
// transition pending → approved/denied is driven OUT OF BAND: a
// PushTransport delivers the auth_req_id (or a derived approval id) to
// the user's device, the device POSTs its decision to an
// operator-supplied callback that calls CIBAStore.SetStatus, and the
// client's /token poll observes the resolved state.
type CIBAStatus string

const (
	// CIBAPending — request issued, user has not yet confirmed.
	// Poll → authorization_pending.
	CIBAPending CIBAStatus = "pending"
	// CIBAApproved — user confirmed out of band. Poll mints tokens.
	CIBAApproved CIBAStatus = "approved"
	// CIBADenied — user explicitly rejected. Poll → access_denied
	// (collapsed to a single error per the oracle-leak contract).
	CIBADenied CIBAStatus = "denied"
)

// CIBARequest is the server-side record for one poll-mode CIBA flow.
// Binds an opaque auth_req_id to the resolved subject + the
// authorization parameters captured at request time, so the eventual
// /token poll mints exactly the consent the user confirmed.
type CIBARequest struct {
	// AuthReqID is the opaque identifier returned to the client and
	// presented back on the /token poll. Minted by the store.
	AuthReqID string
	// ClientID binds the request to the client that initiated it — a
	// request issued for client A cannot be polled by client B.
	ClientID string
	// SubjectID is the resolved end-user the hint identified. Set at
	// issue time (poll mode requires the AS to resolve the hint to a
	// known user before issuing an auth_req_id).
	SubjectID string
	// Provider is the authenticator name recorded for the AMR claim on
	// the eventually-minted token (CIBA Core: the AMR reflects the
	// out-of-band confirmation, here surfaced as this provider name).
	Provider string
	// Scopes is the requested scope set, captured at request time and
	// bound to issuance (the poll never widens scope).
	Scopes []string
	// ACRValues is the requested acr_values string (space-separated),
	// preserved for the token's ACR claim.
	ACRValues string
	// BindingMessage is the human-readable CIBA Core §7.1
	// binding_message shown on both the consumption device and the
	// authentication device so the user can correlate the two.
	BindingMessage string
	// Resources carries RFC 8707 resource indicators captured at
	// request time and bound to issuance.
	Resources []string
	// Nonce is the OIDC nonce threaded onto the id_token when openid
	// scope is granted.
	Nonce string
	// ClientNotificationToken is the CIBA Core §7.1 token the client
	// sends in the backchannel-authentication request in ping/push
	// delivery mode. Captured here and replayed as the bearer credential
	// when the request resolves and the AS pings the client's
	// notification endpoint. Empty in poll mode (no ping fires).
	ClientNotificationToken string
	// RequestContext is the opaque serialized authorization params an
	// operator may want to round-trip (extension members beyond the
	// typed fields above). Stored verbatim; empty for the common case.
	RequestContext []byte
	// Status is the lifecycle state. Issue sets pending.
	Status CIBAStatus
	// Interval is the minimum poll cadence enforced for slow_down.
	Interval time.Duration
	// LastPoll records the most recent poll for slow_down enforcement.
	LastPoll  time.Time
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsExpired reports whether the request's lifetime has elapsed.
func (r *CIBARequest) IsExpired() bool {
	return time.Since(r.ExpiresAt) > 0
}

// CIBAStore persists poll-mode backchannel authentication requests
// between POST /backchannel-authentication (Issue) and the client's
// grant_type=ciba poll on /token (Get + SetStatus + Delete).
//
// Single-resolve + TTL'd + anti-enumeration parity with
// MFAChallengeStore / PushApprovalStore: every missing / expired
// lookup collapses to ErrCIBARequestNotFound so a poller can't
// distinguish "unknown" from "expired". SetStatus refuses to
// re-resolve a terminal entry (UPDATE ... WHERE status='pending'),
// matching the push-approval store.
type CIBAStore interface {
	// Issue mints an auth_req_id, persists the PENDING request, and
	// returns the id. SubjectID + ClientID MUST be set; either empty →
	// ErrCIBARequestInvalid.
	Issue(ctx context.Context, req *CIBARequest) (string, error)

	// Get returns the current request. Missing / expired entries
	// surface as ErrCIBARequestNotFound.
	Get(ctx context.Context, authReqID string) (*CIBARequest, error)

	// SetStatus transitions an entry from Pending to Approved or
	// Denied. Idempotent for a matching transition; refuses changes to
	// an already-resolved request (ErrCIBARequestResolved). Wired by
	// an operator-supplied device-callback handler.
	SetStatus(ctx context.Context, authReqID string, status CIBAStatus) error

	// UpdateLastPoll records the most recent poll for slow_down
	// enforcement.
	UpdateLastPoll(ctx context.Context, authReqID string, t time.Time) error

	// Delete removes an entry (after a successful poll mints tokens,
	// or on a terminal denied poll). Idempotent.
	Delete(ctx context.Context, authReqID string) error

	// ConsumeIfApproved ATOMICALLY deletes and returns the request IFF it is
	// currently approved, so of N concurrent grant_type=ciba polls of one
	// approved auth_req_id exactly ONE wins (gets the record); the rest get
	// ErrCIBARequestNotFound. A pending/denied/unknown/expired request returns
	// ErrCIBARequestNotFound WITHOUT consuming. The /token poll calls this as the
	// single-use claim before minting, so one out-of-band approval can never mint
	// two token sets (race-safe across replicas) — mirrors
	// DeviceCodeStore.ConsumeIfApproved.
	ConsumeIfApproved(ctx context.Context, authReqID string) (*CIBARequest, error)
}

// CIBATransport is the out-of-band delivery seam for the CIBA
// challenge — structurally identical to defaultimpl.PushTransport
// (same Send signature) so an operator can adapt one to the other in
// cmd. Defined here (not as a dependency on defaultimpl) because the
// root sso package wires it and defaultimpl imports the root sso
// package (importing defaultimpl back would cycle). The provider's
// HandleBackchannelAuth calls Send with the auth_req_id + subject + an
// opaque metadata map (binding_message under "binding_message").
type CIBATransport interface {
	Send(ctx context.Context, authReqID, subjectID string, metadata map[string]string) error
}

// CIBAPingNotifier is the CIBA Core §10.2 ping-delivery seam: when a
// backchannel request resolves, the AS POSTs to the client's registered
// notification endpoint to tell it to come collect its tokens (vs. the
// client polling blindly). Like CIBATransport it is operator-wired — the
// implementation knows the client's notification endpoint and POSTs
// {auth_req_id} authenticated with the client_notification_token captured
// at request time. Best-effort by contract: a failed ping degrades to
// poll (the client can still poll /token), never blocks resolution.
//
// nil leaves CIBA in poll-only mode; discovery then advertises only
// "poll" in backchannel_token_delivery_modes_supported.
//
// clientID is supplied so the implementation can route to the client's
// registered notification endpoint (the endpoint is per-client
// registration, the token is per-request).
type CIBAPingNotifier interface {
	Notify(ctx context.Context, clientID, authReqID, clientNotificationToken string) error
}

// CIBAPingNotifierFunc adapts a function to CIBAPingNotifier, mirroring
// CIBATransportFunc.
type CIBAPingNotifierFunc func(ctx context.Context, clientID, authReqID, clientNotificationToken string) error

// Notify calls f.
func (f CIBAPingNotifierFunc) Notify(ctx context.Context, clientID, authReqID, clientNotificationToken string) error {
	return f(ctx, clientID, authReqID, clientNotificationToken)
}

// CIBATransportFunc is a function adapter for CIBATransport. An
// operator wraps a defaultimpl.PushTransport via
// CIBATransportFunc(pt.Send).
type CIBATransportFunc func(ctx context.Context, authReqID, subjectID string, metadata map[string]string) error

// Send implements CIBATransport.
func (f CIBATransportFunc) Send(ctx context.Context, authReqID, subjectID string, metadata map[string]string) error {
	return f(ctx, authReqID, subjectID, metadata)
}

// Sentinel errors. The /token poll collapses every non-approved
// outcome to a single wire error per the oracle-leak contract; these
// provide operator-side observability via audit.
var (
	// ErrCIBARequestNotFound — unknown / expired / consumed id. The
	// token poll maps it to expired_token (mirroring device-flow), so
	// probing can't distinguish the cases.
	ErrCIBARequestNotFound = errors.New("sso: ciba request not found or expired")
	// ErrCIBARequestInvalid — Issue called without the required
	// SubjectID / ClientID.
	ErrCIBARequestInvalid = errors.New("sso: invalid ciba request")
	// ErrCIBARequestResolved — SetStatus attempted on an
	// already-terminal request (clean signal for the
	// legitimate-vs-attacker callback collision in audit).
	ErrCIBARequestResolved = errors.New("sso: ciba request already resolved")
)
